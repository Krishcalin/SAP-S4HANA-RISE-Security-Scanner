/**
 * Security Monitor — the per-domain, per-check posture screen.
 *
 * It must: open on the first domain that has findings and render its check cards
 * (id, title, owner badge); carry the posture band and the annualised-loss
 * headline; keep the four empty-tab meanings distinct (a not_supplied tab says
 * "blind spot", never a clean tick); open a detail drawer on a card; and report a
 * load failure rather than a blank screen.
 */
import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const securityMonitor = vi.fn()
const checkDoc = vi.fn()

vi.mock('../api/client', () => ({
  securityMonitor: (...a: unknown[]) => securityMonitor(...a),
  checkDoc: (...a: unknown[]) => checkDoc(...a),
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
    measured: { systems: 1, oldest: '2026-10-02T00:00:00Z', newest: '2026-10-02T00:00:00Z',
                oldest_days: 1, newest_days: 1, stale_after_days: 35, stale: false },
    context: { systems: 1, standard: 'SAP Security Baseline v2.6',
               sources_supplied: 78, sources_known: 150 },
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
      checks_total: 886, domains: 12, assessed: 1, clear: 9, not_assessed: 2,
      corpus: 2, unplaced: 0,
    },
    ...over,
  }
}

beforeEach(() => {
  vi.clearAllMocks()
  checkDoc.mockResolvedValue({
    check_id: 'AUTH-015', risk: 'Blanket access defeats segregation of duties.',
    mitigation: 'Remove SAP_ALL from dialog accounts.',
  })
})

describe('Security Monitor', () => {
  it('opens on the first domain with findings and renders its check cards', async () => {
    securityMonitor.mockResolvedValue(view())
    render(<MemoryRouter><SecurityMonitor /></MemoryRouter>)

    expect(await screen.findByText('SAP_ALL assigned to dialog users')).toBeInTheDocument()
    expect(screen.getByText('AUTH-015')).toBeInTheDocument()
    expect(screen.getByText('Yours')).toBeInTheDocument()            // owner badge on the card
    expect(screen.getByRole('tab', { name: /Access and Authorization/ })).toBeInTheDocument()
  })

  it('shows the posture band, the context strip and the annualised-loss headline', async () => {
    securityMonitor.mockResolvedValue(view())
    render(<MemoryRouter><SecurityMonitor /></MemoryRouter>)

    expect(await screen.findByText('High risk')).toBeInTheDocument()
    expect(screen.getByText('SAP Security Baseline v2.6')).toBeInTheDocument()
    expect(screen.getByText(/78/)).toBeInTheDocument()               // sources supplied
    expect(screen.getByText(/annualised loss · FAIR P90/)).toBeInTheDocument()
    // the four posture tiles, incl. the not-assessed count (also in the legend)
    expect(screen.getByText('Checks run')).toBeInTheDocument()
    expect(screen.getAllByText('Not assessed').length).toBeGreaterThan(0)
  })

  it('draws a not_supplied tab as a blind spot, not a clean one', async () => {
    securityMonitor.mockResolvedValue(view())
    render(<MemoryRouter><SecurityMonitor /></MemoryRouter>)
    await screen.findByText('SAP_ALL assigned to dialog users')

    fireEvent.click(screen.getByRole('tab', { name: /Patch and Hotnews Management/ }))
    expect(await screen.findByText(/the export this domain reads was not supplied/))
      .toBeInTheDocument()
  })

  it('opens a detail drawer when a check card is clicked', async () => {
    securityMonitor.mockResolvedValue(view())
    render(<MemoryRouter><SecurityMonitor /></MemoryRouter>)
    fireEvent.click(await screen.findByText('SAP_ALL assigned to dialog users'))

    expect(await screen.findByRole('dialog')).toBeInTheDocument()
    expect(screen.getByText('Who fixes it')).toBeInTheDocument()
    // the lazily-fetched remediation text lands in the drawer
    expect(await screen.findByText(/Remove SAP_ALL from dialog accounts/)).toBeInTheDocument()
  })

  it('falls back to printing counts when there is no posture band', async () => {
    securityMonitor.mockResolvedValue(view({ posture: null }))
    render(<MemoryRouter><SecurityMonitor /></MemoryRouter>)
    expect(await screen.findByText(/no honest density to score/)).toBeInTheDocument()
  })

  it('reports a load failure instead of a blank screen', async () => {
    securityMonitor.mockRejectedValue(new Error('boom'))
    render(<MemoryRouter><SecurityMonitor /></MemoryRouter>)
    expect(await screen.findByText(/Could not load the security monitor/))
      .toBeInTheDocument()
  })
})
