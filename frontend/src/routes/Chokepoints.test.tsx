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
  ApiError: class ApiError extends Error {
    status: number
    constructor(status: number, message: string) {
      super(message)
      this.status = status
    }
  },
}))

vi.mock('../lib/title', () => ({ useTitle: () => {} }))

import { chokepoints as fetchChokepoints } from '../api/client'

function row(over: Partial<ChokepointsView['chokepoints'][0]> = {}) {
  return {
    finding_id: 1,
    paths_cut: 1,
    scenarios: ['SAP-RCE-01'],
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
