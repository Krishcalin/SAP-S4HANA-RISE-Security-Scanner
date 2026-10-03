/**
 * Remediation Roadmap screen.
 *
 * THE RULE THIS SCREEN KEEPS. It shows the P1–P4 waves with each finding tagged
 * by owner (yours vs SAP) and renders the honest empty state when there is nothing
 * to sequence — never a blank screen.
 */
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const remediationRoadmap = vi.fn()

vi.mock('../api/client', () => ({
  remediationRoadmap: (...a: unknown[]) => remediationRoadmap(...a),
  ApiError: class ApiError extends Error {
    status: number
    constructor(status: number, message: string) { super(message); this.status = status }
  },
}))
vi.mock('../lib/title', () => ({ useTitle: () => {} }))

import { RemediationRoadmap } from './RemediationRoadmap'

function wave(tier: string, label: string, window: string, items: unknown[] = []) {
  const customer = (items as { customer_fixable: boolean }[]).filter((i) => i.customer_fixable).length
  return { tier, label, window, blurb: `${label} blurb`, items,
           counts: { total: items.length, customer, sap: items.length - customer } }
}

function view(over: Record<string, unknown> = {}) {
  return {
    waves: [
      wave('P1', 'Fix Now', '24-72 hours', [{
        finding_id: 1, check_id: 'PARAM-login/x', title: 'Weak param', severity: 'CRITICAL',
        system_id: 1, sid: 'PRD', owner: 'customer_fixable', owner_label: 'Yours',
        customer_fixable: true, team: 'basis', due_date: '2026-10-06',
      }]),
      wave('P2', 'Fix This Week', 'within 7 days'),
      wave('P3', 'Planned Remediation', 'within 30 days'),
      wave('P4', 'Backlog / Accept', 'next review cycle'),
    ],
    totals: { open: 1, customer_fixable: 1, sap_owned: 0,
              by_tier: { P1: 1, P2: 0, P3: 0, P4: 0 }, systems: 1, measured: null },
    ...over,
  }
}

function empty() {
  return {
    waves: [wave('P1', 'Fix Now', '24-72 hours'), wave('P2', 'Fix This Week', 'within 7 days'),
            wave('P3', 'Planned Remediation', 'within 30 days'), wave('P4', 'Backlog / Accept', 'next review cycle')],
    totals: { open: 0, customer_fixable: 0, sap_owned: 0,
              by_tier: { P1: 0, P2: 0, P3: 0, P4: 0 }, systems: 0, measured: null },
  }
}

function draw() {
  return render(<MemoryRouter><RemediationRoadmap /></MemoryRouter>)
}

beforeEach(() => vi.clearAllMocks())

describe('Remediation Roadmap', () => {
  it('shows a tier wave with a finding tagged by owner', async () => {
    remediationRoadmap.mockResolvedValue(view())
    draw()
    expect(await screen.findByText('Weak param')).toBeInTheDocument()
    expect(screen.getByText('Yours')).toBeInTheDocument()
    expect(screen.getByText('Open findings')).toBeInTheDocument()
  })

  it('shows the honest empty state when nothing is open', async () => {
    remediationRoadmap.mockResolvedValue(empty())
    draw()
    expect(await screen.findByText(/No open findings in scope/)).toBeInTheDocument()
  })

  it('reports a load failure instead of a blank screen', async () => {
    remediationRoadmap.mockRejectedValue(new Error('boom'))
    draw()
    expect(await screen.findByText(/Could not load the remediation roadmap/)).toBeInTheDocument()
  })
})
