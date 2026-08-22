import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { Donut } from './Donut'

/**
 * A distribution mark is mostly arithmetic, and the arithmetic is where it lies.
 *
 * Every failure mode of this form is a number problem wearing a picture: shares
 * computed against the wrong denominator, a present slice rounded away to "0%",
 * a ring drawn out of a total of nothing. None of them look like bugs on screen —
 * they look like a chart — which is exactly why they are worth pinning.
 */

const SEV = [
  { key: 'CRITICAL', label: 'CRITICAL', value: 30, color: 'var(--crit)' },
  { key: 'HIGH', label: 'HIGH', value: 60, color: 'var(--high)' },
  { key: 'LOW', label: 'LOW', value: 10, color: 'var(--low)' },
]

function arcs() {
  const svg = screen.getByRole('img')
  // The track is the first circle and carries no dasharray.
  return Array.from(svg.querySelectorAll('circle'))
    .filter((c) => c.getAttribute('stroke-dasharray'))
}

describe('Donut', () => {
  it('gives every segment a label, a count and a share', () => {
    // Identity is never carried by colour alone. This is also what makes the
    // card readable in monochrome and under forced-colors, with no second
    // encoding invented for those cases.
    render(<Donut slices={SEV} ariaLabel="by severity" />)
    for (const s of SEV) {
      expect(screen.getByText(s.label)).toBeTruthy()
      expect(screen.getByText(String(s.value))).toBeTruthy()
    }
    expect(screen.getByText('30%')).toBeTruthy()
    expect(screen.getByText('60%')).toBeTruthy()
    expect(screen.getByText('10%')).toBeTruthy()
  })

  it('draws one arc per non-zero segment and no arc for a zero', () => {
    // A zero-length arc is invisible but still occupies a legend row, which
    // reads as "present, tiny" rather than "absent".
    render(<Donut ariaLabel="x" slices={[...SEV,
      { key: 'INFO', label: 'INFO', value: 0, color: 'var(--ink-faint)' }]} />)
    expect(arcs()).toHaveLength(3)
    expect(screen.queryByText('INFO')).toBeNull()
  })

  it('uses the passed total as the denominator, not the sum', () => {
    // THE ONE THAT MATTERS. On the dashboard, severity shares are against
    // `open_total`. Re-basing them on the sum of the slices would put every
    // share on the card against a denominator the rest of the page does not use,
    // and the numbers would silently disagree with the KPI above them.
    render(<Donut ariaLabel="x" total={200}
                  slices={[{ key: 'a', label: 'A', value: 50, color: 'red' }]} />)
    expect(screen.getByText('25%')).toBeTruthy()   // 50/200, not 50/50
    expect(screen.getByText('200')).toBeTruthy()   // the hole shows the whole
  })

  it('never rounds a present slice down to zero percent', () => {
    // "0%" beside a count of 1 reads as absent, and the count is right there
    // contradicting it.
    render(<Donut ariaLabel="x" slices={[
      { key: 'big', label: 'Big', value: 9999, color: 'red' },
      { key: 'tiny', label: 'Tiny', value: 1, color: 'blue' },
    ]} />)
    expect(screen.getByText('<1%')).toBeTruthy()
    expect(screen.queryByText('0%')).toBeNull()
  })

  it('never rounds one slice up to 100% while another is on the card', () => {
    render(<Donut ariaLabel="x" slices={[
      { key: 'big', label: 'Big', value: 9999, color: 'red' },
      { key: 'tiny', label: 'Tiny', value: 1, color: 'blue' },
    ]} />)
    expect(screen.getByText('>99%')).toBeTruthy()
    expect(screen.queryByText('100%')).toBeNull()
  })

  it('refuses to draw a ring when the whole is zero', () => {
    // An empty ring claims two things: that the total is nothing, and that the
    // nothing is divided. Only the first is true, so only the first is said.
    render(<Donut ariaLabel="x" slices={[
      { key: 'a', label: 'A', value: 0, color: 'red' },
    ]} />)
    expect(screen.queryByRole('img')).toBeNull()
    expect(screen.getByText(/the total is zero/)).toBeTruthy()
  })

  it('leaves no gap when there is only one segment', () => {
    // The 2px separator exists to keep adjacent arcs apart. With one arc there is
    // no adjacent arc, and the gap would render as a notch in a full ring that
    // means nothing.
    render(<Donut ariaLabel="x" slices={[
      { key: 'a', label: 'A', value: 7, color: 'red' },
    ]} />)
    const [only] = arcs()
    const [len] = (only.getAttribute('stroke-dasharray') || '').split(' ').map(Number)
    const r = Number(only.getAttribute('r'))
    expect(len).toBeCloseTo(2 * Math.PI * r, 1)
  })

  it('separates adjacent arcs so two similar hues read as two marks', () => {
    render(<Donut slices={SEV} ariaLabel="x" />)
    for (const a of arcs()) {
      const [len] = (a.getAttribute('stroke-dasharray') || '').split(' ').map(Number)
      const r = Number(a.getAttribute('r'))
      const frac = len / (2 * Math.PI * r)
      expect(frac).toBeLessThan(1)      // every arc is short of the full ring
    }
  })

  it('carries the total in the hole, so it is a stat tile as well', () => {
    render(<Donut slices={SEV} caption="open" ariaLabel="x" />)
    expect(screen.getByText('100')).toBeTruthy()
    expect(screen.getByText('open')).toBeTruthy()
  })

  it('names itself for a screen reader', () => {
    render(<Donut slices={SEV} ariaLabel="Open findings by severity" />)
    expect(screen.getByRole('img', { name: 'Open findings by severity' })).toBeTruthy()
  })

  it('gives every arc a hover title with its count and share', () => {
    render(<Donut slices={SEV} ariaLabel="x" />)
    const titles = Array.from(screen.getByRole('img').querySelectorAll('title'))
    expect(titles).toHaveLength(3)
    expect(titles[0].textContent).toBe('CRITICAL: 30 (30%)')
  })
})
