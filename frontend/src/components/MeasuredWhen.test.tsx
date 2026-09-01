/**
 * When was this answer measured?
 *
 * THE DEFECT. `queries.latest_coverage` selected the newest complete run per
 * system, ordered by `started_at`, and dropped the timestamp. So Domains, CSF
 * and Trend reported a category CLEAR on the strength of an export of any age
 * and could not say which — a control fed by a scan from March read exactly
 * like one fed this morning.
 */
import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { MeasuredWhen } from './MeasuredWhen'
import type { Measured } from '../api/types'

function measured(over: Partial<Measured> = {}): Measured {
  return {
    systems: 1, oldest: '2026-08-30T00:00:00Z', newest: '2026-08-30T00:00:00Z',
    oldest_days: 2, newest_days: 2, stale_after_days: 35, stale: false,
    ...over,
  }
}

describe('the date under a claim', () => {
  it('says nothing at all when the answer was never dated', () => {
    // Null is not "today". Stamping an undated answer with now is how a
    // manifest nobody supplied becomes a measurement nobody took.
    const { container } = render(
      <MeasuredWhen measured={null} subject="posture" />)
    expect(container).toBeEmptyDOMElement()
  })

  it('dates a current answer without making a fuss of it', () => {
    render(<MeasuredWhen measured={measured()} subject="posture" />)
    expect(screen.getByText(/last measured 2 days ago/)).toBeInTheDocument()
    expect(screen.queryByText(/Patch Day/)).not.toBeInTheDocument()
  })

  it('calls out an answer older than one patch cycle', () => {
    render(<MeasuredWhen
      measured={measured({ oldest_days: 240, stale: true })}
      subject="posture" />)
    expect(screen.getByText(/last measured 240 days ago/)).toBeInTheDocument()
    expect(screen.getByText(/a patch day has passed since/))
      .toBeInTheDocument()
    expect(screen.getByText(/as it was then/)).toBeInTheDocument()
  })

  it('quotes the OLDEST system, not the newest', () => {
    // THE RULE THAT MATTERS. The manifest is a union: a module counts as having
    // run if it ran for any system in scope. So the weakest evidence behind a
    // CLEAR verdict is the oldest run in that union, and quoting the newest
    // would date the answer by its best input rather than its worst.
    render(<MeasuredWhen
      measured={measured({ systems: 4, oldest_days: 300, newest_days: 1,
                           stale: true })}
      subject="posture" />)
    expect(screen.getByText(/Oldest of 4 systems/)).toBeInTheDocument()
    expect(screen.getByText(/300 days ago/)).toBeInTheDocument()
    expect(screen.queryByText(/1 day ago/)).not.toBeInTheDocument()
  })

  it('reads naturally on the day and the day after', () => {
    const { rerender } = render(
      <MeasuredWhen measured={measured({ oldest_days: 0 })} subject="trend" />)
    expect(screen.getByText(/last measured today/)).toBeInTheDocument()
    rerender(
      <MeasuredWhen measured={measured({ oldest_days: 1 })} subject="trend" />)
    expect(screen.getByText(/last measured yesterday/)).toBeInTheDocument()
  })
})
