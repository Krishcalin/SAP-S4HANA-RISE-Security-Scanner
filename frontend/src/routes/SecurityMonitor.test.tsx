/**
 * Security Monitor — the per-domain, per-check posture screen.
 *
 * It must: open on the first domain that has findings and render its check cards
 * (id, title, owner badge); carry the posture band and the annualised-loss
 * headline; keep the four empty-tab meanings distinct (a not_supplied tab says
 * "blind spot", never a clean tick); and report a load failure rather than a
 * blank screen.
 */
import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const securityMonitor = vi.fn()

vi.mock('../api/client', () => ({
  securityMonitor: (...a: unknown[]) => securityMonitor(...a),
  ApiError: class ApiError extends Error {
    status: number
    constructor(status: number, message: string) { super(message); this.status = status }
  },
}))
vi.mock('../lib/title', () => ({ useTitle: () => {} }))

import { SecurityMonitor } from './SecurityMonitor'

const ZERO = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }

function view(over: Record<string, unknown> = {}) {
  return {
    measured: null,
    posture: {
      score: 58, band: 'High', assessed: 120,
      basis: 'Computed over the 120 checks this scan actually ran.',
      anchor: '100 would mean every check that ran found a critical.',
    },
    risk: {
      ale_p90: 3100000, ale_mean: 900000, currency: 'USD',
      priced: false, unrouted: 2, input_finding_count: 40,
    },
    domains: [
      {
        id: 'access', label: 'Access and Authorization', reach: 'full',
        scope: null, blurb: null, state: 'assessed', total: 2,
        counts: { ...ZERO, CRITICAL: 1, HIGH: 1 },
        checks: [{
          check_id: 'AUTH-015', title: 'SAP_ALL assigned to dialog users',
          worst: 'CRITICAL', total: 2, counts: { ...ZERO, CRITICAL: 1, HIGH: 1 },
          owner: 'customer_fixable',
        }],
      },
      {
        id: 'patch', label: 'Patch and Hotnews Management', reach: 'partial',
        scope: null, blurb: null, state: 'not_supplied', total: 0,
        counts: { ...ZERO }, checks: [],
      },
    ],
    totals: {
      findings: 2, counts: { ...ZERO, CRITICAL: 1, HIGH: 1 }, gaps: 1,
      domains: 12, assessed: 1, clear: 9, not_assessed: 2, corpus: 2, unplaced: 0,
    },
    ...over,
  }
}

beforeEach(() => { vi.clearAllMocks() })

describe('Security Monitor', () => {
  it('opens on the first domain with findings and renders its check cards', async () => {
    securityMonitor.mockResolvedValue(view())
    render(<MemoryRouter><SecurityMonitor /></MemoryRouter>)

    expect(await screen.findByText('SAP_ALL assigned to dialog users')).toBeInTheDocument()
    expect(screen.getByText('AUTH-015')).toBeInTheDocument()
    expect(screen.getByText('Yours to fix')).toBeInTheDocument()
    // and the domain is a tab in the strip
    expect(screen.getByRole('tab', { name: /Access and Authorization/ })).toBeInTheDocument()
  })

  it('shows the posture band and the annualised-loss headline', async () => {
    securityMonitor.mockResolvedValue(view())
    render(<MemoryRouter><SecurityMonitor /></MemoryRouter>)

    expect(await screen.findByText('High')).toBeInTheDocument()
    expect(screen.getByText(/score 58\/100/)).toBeInTheDocument()
    expect(screen.getByText('Annualised loss exposure')).toBeInTheDocument()
    // priced:false must disclose the figure is not the customer's own
    expect(screen.getByText(/Illustrative model/)).toBeInTheDocument()
    // the four counts, with not-assessed as its own tile
    expect(screen.getByText('Domains not assessed')).toBeInTheDocument()
  })

  it('draws a not_supplied tab as a blind spot, not a clean one', async () => {
    securityMonitor.mockResolvedValue(view())
    render(<MemoryRouter><SecurityMonitor /></MemoryRouter>)
    await screen.findByText('SAP_ALL assigned to dialog users')

    fireEvent.click(screen.getByRole('tab', { name: /Patch and Hotnews Management/ }))
    expect(await screen.findByText(/the export this domain reads was not supplied/))
      .toBeInTheDocument()
  })

  it('falls back to printing counts when there is no posture band', async () => {
    securityMonitor.mockResolvedValue(view({ posture: null }))
    render(<MemoryRouter><SecurityMonitor /></MemoryRouter>)
    expect(await screen.findByText(/no honest denominator/)).toBeInTheDocument()
  })

  it('reports a load failure instead of a blank screen', async () => {
    securityMonitor.mockRejectedValue(new Error('boom'))
    render(<MemoryRouter><SecurityMonitor /></MemoryRouter>)
    expect(await screen.findByText(/Could not load the security monitor/))
      .toBeInTheDocument()
  })
})
