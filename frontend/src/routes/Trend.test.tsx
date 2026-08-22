import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { Trend } from './Trend'

/**
 * The second defect that type-checked perfectly and shipped.
 *
 * The pass-rate table read `const pct = d.pct_passing ?? 0`. Null means "no
 * module feeding this category ran, so there is no rate" — and `?? 0` turned
 * that into the WORST POSSIBLE SCORE, so a category whose export was never
 * supplied rendered as 0% and sorted to the top of the table as the customer's
 * biggest problem. The server had gone to some trouble to return null rather
 * than a number; one operator threw it away.
 *
 * `??` is invisible to a type-checker: `number | null` narrowed to `number` is
 * exactly what it is for. Only a render assertion can see it.
 */

vi.mock('../api/client', () => ({
  trend: vi.fn(),
  ApiError: class ApiError extends Error {
    status: number
    constructor(status: number, message: string) {
      super(message)
      this.status = status
    }
  },
}))

vi.mock('../lib/title', () => ({ useTitle: () => {} }))

/** A complete, correctly-shaped Journey with everything empty except the rows
 *  under test.
 *
 *  BUILT FROM api/types.ts RATHER THAN GUESSED. The first version invented
 *  plausible field names — `sla: {on_track}`, `mttr: {days}` — and the screen
 *  rendered nothing at all, because the component reads the real ones. A fixture
 *  that does not match the wire type tests a screen the product does not have. */
const journey = (domains: unknown[]) => ({
  sla: {
    by_owner: {},
    overdue_customer: 0,
    due_soon_customer: 0,
    overdue_provider: 0,
    total_tracked: 0,
  },
  aging: [],
  mttr: { window_days: 180, overall: null, by_severity: [], by_team: [], by_owner: [] },
  burndown: [],
  backlog_by_tier: [],
  technical_debt: { stale_over_90d: 0, recurring: [], expired_acceptances: [] },
  teams: [],
  domains,
})

async function renderTrend(domains: unknown[]) {
  const { trend } = await import('../api/client')
  vi.mocked(trend).mockResolvedValue(journey(domains) as never)
  render(<MemoryRouter><Trend /></MemoryRouter>)
  await waitFor(() =>
    expect(screen.getByText(/Pass rate by finding category/)).toBeInTheDocument())
}

describe('a category nothing assessed', () => {
  beforeEach(() => vi.clearAllMocks())

  const unassessed = {
    category: 'Security Audit Log Review',
    checks_known: 12,
    checks_failing: 0,
    pct_passing: null,
    assessed: false,
  }

  it('is not rendered as nought per cent', async () => {
    await renderTrend([unassessed])
    expect(screen.queryByText('0%')).toBeNull()
  })

  it('says it was not assessed instead', async () => {
    await renderTrend([unassessed])
    expect(screen.getByText('not assessed')).toBeInTheDocument()
  })

  it('does not claim a pass rate of any kind', async () => {
    await renderTrend([unassessed])
    expect(screen.queryByText(/%$/)).toBeNull()
  })
})

describe('a category that was assessed', () => {
  beforeEach(() => vi.clearAllMocks())

  it('still shows its rate, including a genuine nought', async () => {
    await renderTrend([{
      category: 'User & Authorization',
      checks_known: 9, checks_failing: 9, pct_passing: 0, assessed: true,
    }])
    // A MEASURED zero is a real result and must still be printed. The defect was
    // never "0% is bad", it was "null became 0%".
    expect(screen.getByText('0%')).toBeInTheDocument()
    expect(screen.queryByText('not assessed')).toBeNull()
  })

  it('shows a partial rate as measured', async () => {
    await renderTrend([{
      category: 'Data Protection & Privacy',
      checks_known: 20, checks_failing: 10, pct_passing: 50, assessed: true,
    }])
    expect(screen.getByText('50%')).toBeInTheDocument()
  })
})
