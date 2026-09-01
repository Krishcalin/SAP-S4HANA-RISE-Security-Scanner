/**
 * When was this answer measured?
 *
 * THE DEFECT. The systems table listed platform, tier, criticality, exposure,
 * mode and owner — and nothing about when any of it was last looked at. On the
 * live sample estate seven systems rendered identically, and two of them
 * (DEV/300 and QAS/200) had never been scanned at all: no complete run, ever.
 * Above that table sat the sentence
 *
 *     Open findings across 7 systems.
 *
 * which counted every REGISTERED system whether or not anything had measured
 * it. The figure was drawn from five and read as a claim about seven.
 *
 * The distinction these tests hold is the one the whole feature turns on: a
 * system nobody has scanned has no age. It must never render as an em dash
 * beside six populated cells, and never as "0 days".
 */
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { Dashboard } from './Dashboard'

vi.mock('../api/client', () => ({
  dashboard: vi.fn(),
  csf: vi.fn(),
  domains: vi.fn(),
  ApiError: class ApiError extends Error {
    status: number
    constructor(status: number, message: string) { super(message); this.status = status }
  },
}))
vi.mock('../lib/title', () => ({ useTitle: () => {} }))

import { csf, dashboard, domains } from '../api/client'

function system(over: Record<string, unknown>) {
  return {
    id: 1, landscape_id: 1, platform: 'abap', external_key: null,
    label: 'PRD/100', sid: 'PRD', client: '100', tier: 'prod',
    product: null, release: null, kernel_patch: null, btp_subaccount: null,
    criticality: 'critical', exposure_zone: 'internal', owner: null,
    tags: [], created_at: '2026-01-01T00:00:00Z',
    landscape_name: 'L', deployment_mode: 'rise_pce',
    last_assessed: '2026-09-01T00:00:00Z', days_since_assessed: 0,
    assessed_runs: 1,
    ...over,
  }
}

function view(systems: unknown[], freshness: Record<string, unknown>) {
  return {
    summary: {
      by_severity: { CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 4 },
      by_remediation_owner: { customer_fixable: 10 },
      by_state: { open: 10 }, open_total: 10,
      expired_acceptances: 0, weak_identity: 0, regressed: 0, sod_trust: null,
    },
    systems,
    freshness: {
      systems: systems.length, current: systems.length, stale: 0,
      never_assessed: 0, stale_after_days: 35, oldest_days: 0,
      never_assessed_labels: [], stale_labels: [],
      ...freshness,
    },
    recent_runs: [], crq: null, crq_scenarios: [],
  }
}

function draw() {
  return render(<MemoryRouter><Dashboard /></MemoryRouter>)
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(csf).mockRejectedValue(new Error('not under test'))
  vi.mocked(domains).mockRejectedValue(new Error('not under test'))
})

describe('the estate says when it was last measured', () => {
  it('does not count a never-scanned system in a claim drawn from findings', async () => {
    vi.mocked(dashboard).mockResolvedValue(view(
      [system({ id: 1 }), system({ id: 2, label: 'DEV/300', last_assessed: null,
                                   days_since_assessed: null, assessed_runs: 0 })],
      { systems: 2, current: 1, never_assessed: 1,
        never_assessed_labels: ['DEV/300'] },
    ) as never)
    draw()
    expect(await screen.findByText(/across 1 of 2 registered systems/))
      .toBeInTheDocument()
    expect(screen.getByText(/never been assessed, so nothing here is a statement/))
      .toBeInTheDocument()
  })

  it('says "never", not a dash, for a system nothing has scanned', async () => {
    // An em dash is what the Owner column shows for "not recorded". Reusing it
    // here would put "nobody has ever looked at this system" in the same
    // visual class as "no owner set".
    vi.mocked(dashboard).mockResolvedValue(view(
      [system({ label: 'DEV/300', last_assessed: null,
                days_since_assessed: null, assessed_runs: 0 })],
      { systems: 1, current: 0, never_assessed: 1, oldest_days: null,
        never_assessed_labels: ['DEV/300'] },
    ) as never)
    draw()
    expect(await screen.findByText('never')).toBeInTheDocument()
  })

  it('names the stale systems and how old the oldest answer is', async () => {
    vi.mocked(dashboard).mockResolvedValue(view(
      [system({ label: 'D01/300', days_since_assessed: 90,
                last_assessed: '2026-06-03T00:00:00Z' })],
      { systems: 1, current: 0, stale: 1, oldest_days: 90,
        stale_labels: ['D01/300'] },
    ) as never)
    draw()
    expect(await screen.findByText(/Last assessed over 35 days ago: D01\/300/))
      .toBeInTheDocument()
    expect(screen.getByText(/oldest answer here is 90 days old/))
      .toBeInTheDocument()
    expect(screen.getByText('90d ago')).toBeInTheDocument()
  })

  it('stays quiet when every system is current', async () => {
    // A banner that is always on is a banner nobody reads. This one has to
    // stay silent on a healthy estate to mean anything on an unhealthy one.
    vi.mocked(dashboard).mockResolvedValue(view([system({})], {}) as never)
    draw()
    await screen.findByText(/across 1 of 1 registered system/)
    await waitFor(() => {
      expect(screen.queryByText(/never been assessed/)).not.toBeInTheDocument()
      expect(screen.queryByText(/Last assessed over/)).not.toBeInTheDocument()
    })
    expect(screen.getByText('today')).toBeInTheDocument()
  })
})
