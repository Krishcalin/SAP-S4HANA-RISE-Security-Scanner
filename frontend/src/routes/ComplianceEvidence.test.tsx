/**
 * Per-control audit evidence screen.
 *
 * THE RULE THIS SCREEN KEEPS. A control that was never tested must never read as
 * a pass: 'clear' and 'not tested' render as distinct states, and the page says
 * in words that clear is an observation, not a certification. Gaps carry their
 * finding evidence.
 */
import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const complianceEvidence = vi.fn()
const complianceDrift = vi.fn()

vi.mock('../api/client', () => ({
  complianceEvidence: (...a: unknown[]) => complianceEvidence(...a),
  complianceDrift: (...a: unknown[]) => complianceDrift(...a),
  evidencePackHref: (f: string) => `/api/compliance/${f}/evidence-pack.html`,
  ApiError: class ApiError extends Error {
    status: number
    constructor(status: number, message: string) { super(message); this.status = status }
  },
}))
vi.mock('../lib/title', () => ({ useTitle: () => {} }))

import { ComplianceEvidence } from './ComplianceEvidence'

const ZERO = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }

function view(over: Record<string, unknown> = {}) {
  return {
    id: 'soxitgc', name: 'SOX / ITGC', subtitle: 'IT general-control domains',
    controls: [
      { id: 'APD', name: 'Access to Programs and Data', themes: ['access-control'],
        status: 'gap', counts: { ...ZERO, HIGH: 1 }, total: 1,
        findings: [{ id: 7, check_id: 'AUTH-015', severity: 'HIGH', priority_tier: 'P2',
                     title: 'SAP_ALL assigned', sid: 'PRD', state: 'open',
                     affected_items: ['user ADMIN1 (PRD/100)'] }] },
      { id: 'CO', name: 'Computer Operations', themes: ['logging-monitoring'],
        status: 'clear', counts: { ...ZERO }, total: 0, findings: [] },
      { id: 'PC', name: 'Program Changes', themes: ['change-management'],
        status: 'not_tested', counts: { ...ZERO }, total: 0, findings: [] },
    ],
    totals: { controls: 3, by_status: { gap: 1, clear: 1, not_tested: 1, not_mapped: 0 },
              findings: 1, measured: null },
    ...over,
  }
}

function driftView(over: Record<string, unknown> = {}) {
  return {
    id: 'soxitgc', name: 'SOX / ITGC', subtitle: 'IT general-control domains',
    has_baseline: true,
    controls: [
      { id: 'APD', name: 'Access to Programs and Data', status: 'gap',
        was: 'clear', change: 'newly_failing' },
      { id: 'CO', name: 'Computer Operations', status: 'clear', was: 'clear',
        change: 'unchanged' },
      { id: 'PC', name: 'Program Changes', status: 'not_tested', was: 'not_tested',
        change: 'unchanged' },
    ],
    totals: { controls: 3, measured: null,
              by_change: { newly_failing: 1, remediated: 0, still_failing: 0,
                           stopped_testing: 0, started_testing: 0, unchanged: 2,
                           no_baseline: 0 } },
    ...over,
  }
}

function draw() {
  return render(
    <MemoryRouter initialEntries={['/compliance/soxitgc']}>
      <Routes>
        <Route path="/compliance/:framework" element={<ComplianceEvidence />} />
      </Routes>
    </MemoryRouter>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  complianceDrift.mockResolvedValue(driftView())
})

describe('Compliance evidence', () => {
  it('shows a gap control with its finding evidence', async () => {
    complianceEvidence.mockResolvedValue(view())
    draw()
    expect(await screen.findByText(/Access to Programs and Data/)).toBeInTheDocument()
    expect(screen.getByText(/SAP_ALL assigned/)).toBeInTheDocument()
    expect(screen.getByText(/user ADMIN1/)).toBeInTheDocument()
    expect(screen.getByText('Gap')).toBeInTheDocument()
  })

  it('distinguishes clear from not-tested', async () => {
    complianceEvidence.mockResolvedValue(view())
    draw()
    expect(await screen.findByText('Clear')).toBeInTheDocument()
    // "Not tested" appears on the control's status pill and in the honesty banner.
    expect(screen.getAllByText('Not tested').length).toBeGreaterThan(0)
    // the standing honesty sentence
    expect(screen.getByText(/Clear is not a certification/)).toBeInTheDocument()
  })

  it('summarises control drift since the previous scan and badges the change', async () => {
    complianceEvidence.mockResolvedValue(view())
    complianceDrift.mockResolvedValue(driftView())
    draw()
    expect(await screen.findByText(/Since the previous scan/)).toBeInTheDocument()
    expect(screen.getByText(/↑ newly failing/)).toBeInTheDocument()
  })

  it('offers a download of the evidence pack for this framework', async () => {
    complianceEvidence.mockResolvedValue(view())
    draw()
    const link = await screen.findByRole('link', { name: /Download evidence pack/ })
    expect(link).toHaveAttribute('href', '/api/compliance/soxitgc/evidence-pack.html')
  })

  it('reports an unknown framework', async () => {
    const { ApiError } = await import('../api/client') as unknown as
      { ApiError: new (s: number, m: string) => Error }
    complianceEvidence.mockRejectedValue(new ApiError(404, 'nope'))
    draw()
    expect(await screen.findByText(/Unknown compliance framework/)).toBeInTheDocument()
  })

  it('reports a load failure instead of a blank screen', async () => {
    complianceEvidence.mockRejectedValue(new Error('boom'))
    draw()
    expect(await screen.findByText(/Could not load the control evidence/))
      .toBeInTheDocument()
  })
})
