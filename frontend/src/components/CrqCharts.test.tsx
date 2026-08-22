/*
 * Copyright (c) 2026 Krishnendu De. All Rights Reserved.
 *
 * Author : Krishnendu De
 * Coding Assistance : Claude Code
 * Code Security Assistance : Code QL
 */

import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { RiskTrend } from './CrqCharts'
import type { CrqTrendPoint } from '../api/types'

/**
 * The break annotations on the exposure trend, and whether they can be read.
 *
 * THE DEFECT. Every break printed "inputs changed" at the same y, so a run of
 * single-point groups stacked four copies of it inside the width of one. On a
 * chart whose heading is "Has the exposure actually fallen?" that annotation is
 * the load-bearing text: it is what says two segments are NOT comparable, so a
 * reader who cannot read it is left comparing numbers the model says nothing
 * about.
 *
 * Nothing failed, because the chart tests that existed asserted the SERIES —
 * that the line breaks where the fingerprint changes — and a broken line with
 * illegible labels satisfies that completely.
 *
 * These tests are geometry, on rendered SVG attributes in jsdom, for the same
 * reason the risk-path diagram's are: it is plain SVG, so where things ARE is
 * as checkable as what they say.
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

/** The reported shape: several single-point groups in a row, so their midpoints
 *  land within a label's width of each other. */
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

function labels() {
  const svg = screen.getByRole('img', { name: /Annual loss exposure per scan/ })
  return Array.from(svg.querySelectorAll('text'))
    .filter((t) => (t.textContent || '').trim() === 'inputs changed')
    .map((t) => ({ x: Number(t.getAttribute('x')), y: Number(t.getAttribute('y')) }))
}

/** Estimated advance width of the label, matching the component's own estimate. */
const LABEL_W = 'inputs changed'.length * 12 * 0.53

describe('RiskTrend break annotations', () => {
  it('never overlaps two labels on the same row', () => {
    render(<RiskTrend points={crowded()} />)
    const placed = labels()
    expect(placed.length).toBeGreaterThan(0)

    const byRow = new Map<number, number[]>()
    for (const l of placed) {
      byRow.set(l.y, [...(byRow.get(l.y) ?? []), l.x])
    }
    for (const [y, xs] of byRow) {
      const sorted = [...xs].sort((a, b) => a - b)
      for (let i = 1; i < sorted.length; i++) {
        expect(sorted[i] - sorted[i - 1]).toBeGreaterThanOrEqual(LABEL_W)
      }
      expect(y).toBeGreaterThan(0)
    }
  })

  it('uses more than one row when the breaks are crowded', () => {
    // The fix is rows. If everything lands on one y again, the placement pass has
    // been removed or defeated and the first test would only be passing because
    // the fixture stopped being crowded.
    render(<RiskTrend points={crowded()} />)
    const rows = new Set(labels().map((l) => l.y))
    expect(rows.size).toBeGreaterThan(1)
  })

  it('draws a divider for every break, labelled or not', () => {
    // The break is the fact; the words are the explanation. Dropping a label must
    // never drop the divider, or the chart would show a continuous-looking series
    // across an incomparable change.
    render(<RiskTrend points={crowded()} />)
    const svg = screen.getByRole('img', { name: /Annual loss exposure per scan/ })
    const dashed = Array.from(svg.querySelectorAll('line'))
      .filter((l) => l.getAttribute('stroke-dasharray') === '2 3')
    // Six fingerprint changes in the fixture; each contributes at least its own
    // full-height divider.
    const uniqueX = new Set(dashed.map((l) => l.getAttribute('x1')))
    expect(uniqueX.size).toBe(6)
  })

  it('says so in the caption when a label had to be dropped', () => {
    // Silently omitting annotations is how a chart comes to under-report the very
    // thing it exists to flag. This fixture is dense enough to exhaust the rows.
    const dense: CrqTrendPoint[] = []
    for (let i = 0; i < 24; i++) dense.push(pt(i + 1, `fp${i}`, 10_000_000))
    render(<RiskTrend points={dense} />)
    expect(screen.getByText(/drawn\s+without a label/)).toBeTruthy()
  })

  it('is silent about dropped labels when none were dropped', () => {
    // The absence case. A caption that always warned would be one nobody reads.
    render(<RiskTrend points={[pt(1, 'a', 1e7), pt(2, 'a', 9e6), pt(3, 'b', 8e6)]} />)
    expect(screen.queryByText(/drawn\s+without a label/)).toBeNull()
  })

  it('does not letterbox itself into a fraction of the card', () => {
    // With a `height` attribute alongside width="100%", preserveAspectRatio fits
    // the viewBox to the shorter side and the chart draws at 1:1, centred, in a
    // card twice its width — which is what left the labels no room in the first
    // place.
    render(<RiskTrend points={crowded()} />)
    const svg = screen.getByRole('img', { name: /Annual loss exposure per scan/ })
    expect(svg.getAttribute('width')).toBe('100%')
    expect(svg.getAttribute('height')).toBeNull()
  })

  it('still refuses to draw a trend from a single point', () => {
    render(<RiskTrend points={[pt(1, 'a', 1e7)]} />)
    expect(screen.getByText(/One point is a reading, not a direction/)).toBeTruthy()
  })
})
