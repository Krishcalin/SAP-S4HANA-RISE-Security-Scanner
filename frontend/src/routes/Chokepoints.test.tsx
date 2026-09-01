import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { Chokepoints } from './Chokepoints'
import type { ChokepointsView } from '../api/types'

/**
 * The choke-point worklist as its own screen.
 *
 * Two claims on this page can be wrong in ways that look right, and both are
 * about counting:
 *
 *   "OPEN PATHS" IS NOT THE SUM OF THE SEVERS COLUMN. Most paths have more than
 *   one cut, so adding that column counts them repeatedly — and the result is
 *   larger than the number of paths that exist, which nobody notices because it
 *   is a bigger number in a box on a dashboard.
 *
 *   A CAPPED LIST LOOKS LIKE A COMPLETE ONE. Stopping at exactly the limit is
 *   indistinguishable from happening to end there, and the difference matters
 *   when the thing being read is "everything worth fixing first".
 */

vi.mock('../api/client', () => ({
  chokepoints: vi.fn(),
  severingSets: vi.fn(),
  ApiError: class ApiError extends Error {
    status: number
    constructor(status: number, message: string) {
      super(message)
      this.status = status
    }
  },
}))

vi.mock('../lib/title', () => ({ useTitle: () => {} }))

import { chokepoints as fetchChokepoints,
         severingSets as fetchSeveringSets } from '../api/client'

function row(over: Partial<ChokepointsView['chokepoints'][0]> = {}) {
  return {
    finding_id: 1,
    paths_cut: 1,
    scenarios: ['SAP-RCE-01'],
    scenario_detail: null,
    ale_severed: null,
    check_id: 'INTG-GW-001',
    severity: 'CRITICAL' as const,
    state: 'open' as const,
    priority_tier: 'P1' as const,
    remediation_owner: 'customer_fixable' as const,
    title: 'Gateway secinfo has overly permissive permit rules',
    sid: 'PRD',
    client: '100',
    ...over,
  }
}

function view(over: Partial<ChokepointsView> = {}): ChokepointsView {
  return {
    chokepoints: [row()],
    truncated: false,
    summary: { total: 1, multi_path: 0, customer_fixable: 1, open_paths: 1 },
    ...over,
  }
}

// The plans panel fetches separately from the worklist. Defaulted at FILE level
// rather than inside one describe: the block that tests the money sits in
// another, and a default that only covers the block somebody edited is how a
// component change breaks tests that have nothing to do with it.
beforeEach(() => {
  vi.mocked(fetchSeveringSets).mockResolvedValue({ scenarios: [] })
})

function draw(v: ChokepointsView) {
  vi.mocked(fetchChokepoints).mockResolvedValue(v)
  render(<MemoryRouter><Chokepoints /></MemoryRouter>)
}

describe('Choke Points', () => {
  beforeEach(() => vi.clearAllMocks())

  it('ranks by consequence and shows how many paths each fix severs', async () => {
    draw(view({
      chokepoints: [
        row({ finding_id: 1, paths_cut: 3, check_id: 'INTG-GW-001' }),
        row({ finding_id: 2, paths_cut: 1, check_id: 'NET-005' }),
      ],
      summary: { total: 2, multi_path: 1, customer_fixable: 2, open_paths: 4 },
    }))
    await waitFor(() => expect(screen.getByText('INTG-GW-001')).toBeTruthy())
    expect(screen.getByText('3')).toBeTruthy()
    expect(screen.getByText('NET-005')).toBeTruthy()
  })

  it('does not report open paths as the sum of the severs column', async () => {
    // Two rows severing 3 and 1 sum to 4, and there are 2 open paths — because
    // both findings cut the same paths. Rendering 4 would claim more paths exist
    // than do, in the most authoritative place on the screen.
    draw(view({
      chokepoints: [row({ finding_id: 1, paths_cut: 3 }), row({ finding_id: 2, paths_cut: 1 })],
      summary: { total: 2, multi_path: 1, customer_fixable: 2, open_paths: 2 },
    }))
    await waitFor(() => expect(screen.getByText('what there is to sever')).toBeTruthy())
    const card = screen.getByText('Open paths').closest('div')!
    expect(card.textContent).toContain('2')
    expect(card.textContent).not.toContain('4')
  })

  it('says when the list is capped', async () => {
    draw(view({ truncated: true }))
    await waitFor(() => expect(screen.getByText(/This list is capped/)).toBeTruthy())
  })

  it('says nothing about capping when the list is complete', async () => {
    // The absence case. A banner that always shows is one nobody reads.
    draw(view({ truncated: false }))
    await waitFor(() => expect(screen.getByText('The worklist')).toBeTruthy())
    expect(screen.queryByText(/This list is capped/)).toBeNull()
  })

  it('explains an empty worklist instead of showing a blank table', async () => {
    // "No choke points" is a real result and reads badly unexplained: it means no
    // OPEN path currently has a cut you can close, not that the model found
    // nothing wrong.
    draw(view({
      chokepoints: [],
      summary: { total: 0, multi_path: 0, customer_fixable: 0, open_paths: 0 },
    }))
    await waitFor(() => expect(screen.getByText(/No choke points/)).toBeTruthy())
    expect(screen.getByText(/different statement from/)).toBeTruthy()
  })

  it('links a row to its finding, not to the check definition', async () => {
    // The row is one defect on one system. The definition is reachable from the
    // finding's own page; sending the reader there instead would lose the defect
    // they clicked.
    draw(view({ chokepoints: [row({ finding_id: 42 })] }))
    await waitFor(() => expect(screen.getByText('INTG-GW-001')).toBeTruthy())
    expect(screen.getByText('INTG-GW-001').closest('a')!.getAttribute('href'))
      .toBe('/findings/42')
  })

  it('refuses gracefully when the account cannot see the model', async () => {
    const { ApiError } = await import('../api/client')
    vi.mocked(fetchChokepoints).mockRejectedValue(new (ApiError as never as
      new (s: number, m: string) => Error)(403, 'nope'))
    render(<MemoryRouter><Chokepoints /></MemoryRouter>)
    await waitFor(() => expect(screen.getByText(/not permitted/)).toBeTruthy())
  })
})

describe('what a cut is worth', () => {
  it('shows the money only where the fix closes a scenario outright', async () => {
    draw(view({
      chokepoints: [row({
        ale_severed: 4_000_000,
        scenario_detail: [{
          scenario: 'SAP-RCE-01', paths_cut: 2, paths_open: 2,
          severs_all: true, ale_mean: 4_000_000, ale_p90: 8_000_000,
        }],
      })],
    }))
    expect(await screen.findByText('$4M')).toBeInTheDocument()
    expect(screen.getByText(/closes SAP-RCE-01 outright/)).toBeInTheDocument()
  })

  it('says how many of how many routes a partial cut closes', async () => {
    // The sentence that stops somebody reading a partial cut as a closure.
    draw(view({
      chokepoints: [row({
        ale_severed: null,
        scenario_detail: [{
          scenario: 'SAP-RCE-01', paths_cut: 1, paths_open: 4,
          severs_all: false, ale_mean: 4_000_000, ale_p90: 8_000_000,
        }],
      })],
    }))
    expect(await screen.findByText(/SAP-RCE-01: 1 of 4 routes/)).toBeInTheDocument()
  })

  it('renders an em dash, never a zero, where there is no figure', async () => {
    // "$0" is a claim that the exposure was computed and came to nothing.
    // This is the absence of a computation. See lib/pricing.ts.
    draw(view({ chokepoints: [row({ ale_severed: null })] }))
    await screen.findByText('INTG-GW-001')
    expect(screen.queryByText('$0')).not.toBeInTheDocument()
    expect(screen.getAllByText('—').length).toBeGreaterThan(0)
  })
})

describe('what it takes to close a scenario', () => {
  function plan(over = {}) {
    return {
      scenario: 'SAP-RCE-01', paths_open: 4, closable: true, reason: '',
      ale_mean: 13_215_270,
      fixes: [
        { finding_id: 7, check_id: 'INTG-GW-001', severity: 'CRITICAL' as const,
          remediation_owner: 'customer_fixable' as const,
          title: 'Gateway secinfo has overly permissive permit rules',
          sid: 'PRD', client: '100' },
        { finding_id: 8, check_id: 'NET-004', severity: 'HIGH' as const,
          remediation_owner: 'customer_fixable' as const,
          title: 'High-risk ICF services are active', sid: 'PRD', client: '100' },
      ],
      ...over,
    }
  }

  it('answers the question the empty Worth column raises', async () => {
    // Every row of the worklist shows a dash on a real estate, because no
    // single fix severs a scenario. This panel says what does.
    vi.mocked(fetchSeveringSets).mockResolvedValue({ scenarios: [plan()] })
    draw(view())
    expect(await screen.findByText(/2 fixes close all 4 routes/)).toBeInTheDocument()
    expect(screen.getByText('$13.22M')).toBeInTheDocument()
    // Twice: once in the plan above, once on its own row in the worklist
    // below. The default fixture uses this check id for both.
    expect(screen.getAllByText('INTG-GW-001').length).toBe(2)
  })

  it('says no set closes it rather than offering one that does not', async () => {
    // A route with no severable hop means NO plan closes this scenario. Showing
    // a plan anyway would be a false all-clear, which is worse than no answer.
    vi.mocked(fetchSeveringSets).mockResolvedValue({
      scenarios: [plan({
        closable: false, fixes: [],
        reason: 'one of these routes has no hop that closing a finding would sever',
      })],
    })
    draw(view())
    expect(await screen.findByText(/No set of fixes closes this/)).toBeInTheDocument()
    expect(screen.queryByText(/fixes close all/)).not.toBeInTheDocument()
  })

  it('gives the plan even when nobody has priced the business', async () => {
    // The set is a fact about the graph. Only the money needs the answers.
    vi.mocked(fetchSeveringSets).mockResolvedValue({
      scenarios: [plan({ ale_mean: null })],
    })
    draw(view())
    expect(await screen.findByText(/2 fixes close all 4 routes/)).toBeInTheDocument()
    expect(screen.queryByText('$0')).not.toBeInTheDocument()
  })

  it('stays out of the way when the panel has nothing to say', async () => {
    vi.mocked(fetchSeveringSets).mockResolvedValue({ scenarios: [] })
    draw(view())
    await screen.findByText('INTG-GW-001')
    expect(screen.queryByText(/What it takes to close/)).not.toBeInTheDocument()
  })
})
