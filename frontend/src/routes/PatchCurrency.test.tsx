/**
 * Patch Currency screen.
 *
 * THE RULE THIS SCREEN KEEPS. An estate we could not assess must never read as
 * current: a `not_assessed` view shows the "no applied-notes export" banner, not a
 * reassuring zero. The band verdict and the facts it rests on (oldest unapplied,
 * actively-exploited-and-open) are shown, and no percentage appears.
 */
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const patchCurrency = vi.fn()

vi.mock('../api/client', () => ({
  patchCurrency: (...a: unknown[]) => patchCurrency(...a),
  ApiError: class ApiError extends Error {
    status: number
    constructor(status: number, message: string) { super(message); this.status = status }
  },
}))
vi.mock('../lib/title', () => ({ useTitle: () => {} }))

import { PatchCurrency } from './PatchCurrency'

const BANDS = [
  { id: 'fresh', label: '0–30 days', count: 0 },
  { id: 'recent', label: '31–90 days', count: 0 },
  { id: 'ageing', label: '91–180 days', count: 0 },
  { id: 'old', label: '181–365 days', count: 0 },
  { id: 'over_a_year', label: 'over a year', count: 2 },
]

function behind(over: Record<string, unknown> = {}) {
  return {
    band: 'critically_behind', assessed: true,
    oldest: { note: '300', released: '2024-10', exploited: false, cvss: 9.8, priority: 'High', age_days: 430 },
    exploited_missing: { count: 1, notes: [
      { note: '200', released: '2025-10', exploited: true, cvss: 10, priority: 'HotNews', age_days: 90 }] },
    age_bands: BANDS,
    undated: { count: 0, notes: [] },
    by_priority: { HotNews: 1, High: 1 },
    sp_stack: null, sp_out_of_date: false,
    catalogue: { catalogue_size: 120, curated_through: '2025-12' },
    totals: { missing: 2, dated: 2, measured: null },
    ...over,
  }
}

function notAssessed() {
  return {
    band: 'not_assessed', assessed: false, oldest: null,
    exploited_missing: { count: 0, notes: [] },
    age_bands: BANDS.map((b) => ({ ...b, count: 0 })),
    undated: { count: 0, notes: [] }, by_priority: {},
    sp_stack: null, sp_out_of_date: false, catalogue: null,
    totals: { missing: 0, dated: 0, measured: null },
  }
}

function draw() {
  return render(<MemoryRouter><PatchCurrency /></MemoryRouter>)
}

beforeEach(() => vi.clearAllMocks())

describe('Patch currency', () => {
  it('shows the band verdict and the facts it rests on', async () => {
    patchCurrency.mockResolvedValue(behind())
    draw()
    expect(await screen.findByText('Critically behind')).toBeInTheDocument()
    // the actively-exploited-and-open section and its note
    expect(screen.getByText(/Actively exploited and still open/)).toBeInTheDocument()
    expect(screen.getByText(/Note 200/)).toBeInTheDocument()
    // the oldest unapplied note
    expect(screen.getByText(/Note 300/)).toBeInTheDocument()
    // the age histogram
    expect(screen.getByText('over a year')).toBeInTheDocument()
  })

  it('never reads as current when not assessed', async () => {
    patchCurrency.mockResolvedValue(notAssessed())
    draw()
    expect(await screen.findByText('Not assessed')).toBeInTheDocument()
    // Phrase unique to the "supply this export" banner (the band note also
    // mentions the missing export).
    expect(screen.getByText(/currency cannot be judged/)).toBeInTheDocument()
    expect(screen.queryByText('Current')).not.toBeInTheDocument()
  })

  it('shows no percentage figure', async () => {
    patchCurrency.mockResolvedValue(behind())
    const { container } = draw()
    expect(await screen.findByText('Critically behind')).toBeInTheDocument()
    expect(container.textContent).not.toMatch(/%/)
  })

  it('reports a load failure instead of a blank screen', async () => {
    patchCurrency.mockRejectedValue(new Error('boom'))
    draw()
    expect(await screen.findByText(/Could not load the patch-currency view/))
      .toBeInTheDocument()
  })
})
