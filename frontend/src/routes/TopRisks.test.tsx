/**
 * The worst five in each domain.
 *
 * THE RULE THIS SCREEN EXISTS TO KEEP. An empty card is four different things
 * — assessed, clear, not_supplied, not_assessed — and only one of them is good
 * news. Drawing them alike turns "the export never arrived" into "nothing found
 * here", which is the failure this whole product is built against.
 */
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const topRisks = vi.fn()

vi.mock('../api/client', () => ({
  topRisks: (...a: unknown[]) => topRisks(...a),
  ApiError: class ApiError extends Error {
    status: number
    constructor(status: number, message: string) { super(message); this.status = status }
  },
}))
vi.mock('../lib/title', () => ({ useTitle: () => {} }))

import { TopRisks } from './TopRisks'

function risk(over: Record<string, unknown> = {}) {
  return {
    id: 1, check_id: 'PARAM-LOGIN/MIN_PASSWORD_LNG', severity: 'HIGH',
    priority_tier: 'P2', priority_score: 71, state: 'open',
    category: 'Password Policy', title: 'Password minimum length below baseline',
    sid: 'PRD', system_client: '100', instances: 1, systems: ['PRD'],
    ...over,
  }
}

function domain(over: Record<string, unknown> = {}) {
  return {
    id: 'baselining', label: 'Baselining and Benchmarking', state: 'assessed',
    total: 1, counts: { CRITICAL: 0, HIGH: 1 }, shown: [risk()], not_shown: 0,
    distinct: 1,
    ...over,
  }
}

function view(domains: unknown[]) {
  return { domains, per_domain: 5, measured: null }
}

function draw() {
  return render(<MemoryRouter><TopRisks /></MemoryRouter>)
}

beforeEach(() => { vi.clearAllMocks() })

describe('the five worst in each domain', () => {
  it('lists the findings with the tier that ranked them', async () => {
    // The tier is what ordered the row, so it is shown rather than left as
    // invisible reasoning behind a rank.
    topRisks.mockResolvedValue(view([domain()]))
    draw()
    expect(await screen.findByText(/Password minimum length below baseline/))
      .toBeInTheDocument()
    expect(screen.getByText('P2')).toBeInTheDocument()
    expect(screen.getByText('HIGH')).toBeInTheDocument()
  })

  it('says how many it is NOT showing', async () => {
    // "5" invites a reader to think they have seen the domain. "5 of 138"
    // does not.
    topRisks.mockResolvedValue(view([
      domain({ total: 143, distinct: 135, not_shown: 133,
               shown: [risk({ id: 1 }), risk({ id: 2, check_id: 'X' })] }),
    ]))
    draw()
    // The denominator is DISTINCT risks, which is what the five are drawn
    // from — not the finding count, which is larger whenever one problem
    // lands on several systems.
    expect(await screen.findByText(/Showing 2 of 135 distinct risks/))
      .toBeInTheDocument()
    expect(screen.getByText(/across 143 findings/)).toBeInTheDocument()
    expect(screen.getByText(/133 more in this domain/)).toBeInTheDocument()
  })

  it('distinguishes "we looked and found nothing" from "nothing was looked at"',
    async () => {
      topRisks.mockResolvedValue(view([
        domain({ id: 'access', label: 'Access', state: 'clear',
                 total: 0, shown: [], not_shown: 0 }),
        domain({ id: 'patch', label: 'Patch', state: 'not_supplied',
                 total: 0, shown: [], not_shown: 0 }),
      ]))
      draw()
      expect(await screen.findByText(/assessed and came back empty/))
        .toBeInTheDocument()
      // The one that matters: an absent export must never read as clean.
      expect(screen.getByText(/the export this domain reads never arrived/))
        .toBeInTheDocument()
      expect(screen.getByText(/This is not a clean result/))
        .toBeInTheDocument()
    })

  it('says a domain outside the product is a boundary, not a problem', async () => {
    topRisks.mockResolvedValue(view([
      domain({ id: 'exploit', label: 'Exploit', state: 'not_assessed',
               total: 0, shown: [], not_shown: 0 }),
    ]))
    draw()
    expect(await screen.findByText(/Not covered by this product in any run/))
      .toBeInTheDocument()
  })

  it('counts the domains that listed nothing because nothing was assessed',
    async () => {
      topRisks.mockResolvedValue(view([
        domain(),
        domain({ id: 'patch', state: 'not_supplied', shown: [], total: 0 }),
        domain({ id: 'exploit', state: 'not_assessed', shown: [], total: 0 }),
      ]))
      draw()
      expect(await screen.findByText(/2 domains listed nothing/))
        .toBeInTheDocument()
      expect(screen.getByText(/an empty card is not the same as a clean one/))
        .toBeInTheDocument()
    })

  it('shows the systems when one risk lands on several', async () => {
    // One problem on six systems is one risk — and the reader still has to
    // know it is six.
    topRisks.mockResolvedValue(view([
      domain({ shown: [risk({ instances: 6, system_count: 6,
                              systems: ['PRD', 'D01', 'T01', 'Q01', 'S01', 'X01'] })] }),
    ]))
    draw()
    expect(await screen.findByText(/6 systems: PRD, D01, T01/)).toBeInTheDocument()
    expect(screen.getByText(/\+3/)).toBeInTheDocument()
  })

  it('counts systems, not findings', async () => {
    // THIS TEST USED TO ASSERT THE BUG. Its fixture said instances: 6 with four
    // SIDs and expected "6 systems", because `instances` counts FINDINGS: one
    // system with two clients gives two findings on one SID, and two systems in
    // different landscapes can share a SID. Measured on an eight-system estate,
    // the screen read "9 systems" while naming eight.
    topRisks.mockResolvedValue(view([
      domain({ shown: [risk({ instances: 6, system_count: 4,
                              systems: ['PRD', 'D01', 'T01', 'Q01'] })] }),
    ]))
    draw()
    expect(await screen.findByText(/4 systems \(6 findings\)/)).toBeInTheDocument()
    expect(screen.queryByText(/6 systems/)).not.toBeInTheDocument()
  })

  it('counts the unnamed remainder off the system total, not the name list',
    async () => {
      // Two systems sharing a SID contribute one name, so "+N" taken from the
      // name list left the reader adding 3 and 5 and getting 8 beside a stated 9.
      topRisks.mockResolvedValue(view([
        domain({ shown: [risk({ instances: 9, system_count: 9,
                                systems: ['PRD', 'D01', 'T01', 'Q01', 'S01',
                                          'X01', 'Y01', 'Z01'] })] }),
      ]))
      draw()
      await screen.findByText(/9 systems/)
      expect(screen.getByText(/\+6/)).toBeInTheDocument()
    })

  it('falls back to the name list when an older server sends no count',
    async () => {
      topRisks.mockResolvedValue(view([
        domain({ shown: [risk({ instances: 2, systems: ['PRD', 'D01'] })] }),
      ]))
      draw()
      expect(await screen.findByText(/2 systems: PRD, D01/)).toBeInTheDocument()
    })

  it('says nothing of the sort when every domain was assessed', async () => {
    // A caveat that is always on is a caveat nobody reads.
    topRisks.mockResolvedValue(view([domain()]))
    draw()
    await screen.findByText(/Password minimum length/)
    expect(screen.queryByText(/listed nothing/)).not.toBeInTheDocument()
  })

  it('renders every domain, including the empty ones', async () => {
    // Dropping empty cards would shorten the page to the domains that happen
    // to have findings — and the ones that do not are exactly where "was this
    // assessed?" needs answering.
    topRisks.mockResolvedValue(view([
      domain({ id: 'a', label: 'Alpha' }),
      domain({ id: 'b', label: 'Beta', state: 'clear', shown: [], total: 0 }),
      domain({ id: 'c', label: 'Gamma', state: 'not_supplied', shown: [], total: 0 }),
    ]))
    draw()
    expect(await screen.findByText('Alpha')).toBeInTheDocument()
    expect(screen.getByText('Beta')).toBeInTheDocument()
    expect(screen.getByText('Gamma')).toBeInTheDocument()
  })
})
