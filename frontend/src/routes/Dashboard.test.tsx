import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { Dashboard } from './Dashboard'

/**
 * The quantification funnel, and the rule it must not break to fix.
 *
 * ONE PRICED LANDSCAPE OUT OF THREE. The dollar figure is the one output neither
 * incumbent produces, and it was invisible on the page everybody lands on unless
 * somebody had already supplied the inputs — because `isPriced` gated the whole
 * feature rather than only the number. A customer who never opened /risk never
 * learned it existed.
 *
 * THE RULE THAT STAYS. `isPriced` gates the FIGURE everywhere, because the
 * shipped catalogue is calibrated to an illustrative $1bn manufacturer and
 * printing that company's losses under a customer's name is a fabrication rather
 * than an estimate. A card nobody can screenshot is the only caveat that survives
 * being screenshotted.
 *
 * So the two tests that matter here are a pair: the invitation appears when
 * nothing is priced, and no currency figure appears with it. Fixing the funnel by
 * relaxing the gate would pass the first and fail the second.
 */

vi.mock('../api/client', () => ({
  dashboard: vi.fn(),
  csf: vi.fn(),
  compliance: vi.fn(),
  domains: vi.fn(),
  ApiError: class ApiError extends Error {
    status: number
    constructor(status: number, message: string) {
      super(message)
      this.status = status
    }
  },
}))

vi.mock('../lib/title', () => ({ useTitle: () => {} }))

import { compliance, csf, dashboard, domains } from '../api/client'

const CRQ_PRICED = {
  id: 1, scan_run_id: 1, scenario_id: null,
  ale_p10: 1_000_000, ale_p50: 4_200_000, ale_p90: 9_100_000, ale_mean: 5_000_000,
  unrouted_count: 0, input_finding_count: 318,
  detail: { loss_model: { applied: true } },
  computed_at: '2026-08-20T00:00:00Z', started_at: '2026-08-20T00:00:00Z',
  run_id: 1, sid: 'PRD', client: '100',
}

function view(crq: unknown) {
  return {
    summary: {
      by_severity: { CRITICAL: 12, HIGH: 90, MEDIUM: 140, LOW: 76 },
      by_remediation_owner: { customer_fixable: 300 },
      by_state: { open: 318 },
      open_total: 318,
      expired_acceptances: 0,
      weak_identity: 0,
      regressed: 0,
      sod_trust: null,
    },
    systems: [],
    freshness: {
      systems: 0, current: 0, stale: 0, never_assessed: 0,
      stale_after_days: 35, oldest_days: null,
      never_assessed_labels: [], stale_labels: [],
    },
    recent_runs: [],
    crq,
    crq_scenarios: [],
  }
}

function renderPage() {
  return render(<MemoryRouter><Dashboard /></MemoryRouter>)
}

describe('Dashboard — the quantification funnel', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    // The CSF strip and the domain strip each make their own request and each
    // swallow their own failure by design — twelve empty tiles would read as
    // "nothing wrong in any domain". Rejecting them here uses that behaviour to
    // keep this file about the CRQ card, rather than pinning two unrelated
    // response shapes that would then have to be maintained here.
    vi.mocked(csf).mockRejectedValue(new Error('not under test'))
    vi.mocked(compliance).mockRejectedValue(new Error('not under test'))
    vi.mocked(domains).mockRejectedValue(new Error('not under test'))
  })

  it('invites pricing when the landscape has no answers', async () => {
    vi.mocked(dashboard).mockResolvedValue(view({
      ...CRQ_PRICED, detail: { loss_model: { applied: false } },
    }) as never)
    renderPage()
    await waitFor(() =>
      expect(screen.getByText(/no loss figure yet/i)).toBeTruthy())
    expect(screen.getByText(/Supply your figures/)).toBeTruthy()
  })

  it('shows no currency figure while inviting', async () => {
    vi.mocked(dashboard).mockResolvedValue(view({
      ...CRQ_PRICED, detail: { loss_model: { applied: false } },
    }) as never)
    const { container } = renderPage()
    await waitFor(() =>
      expect(screen.getByText(/no loss figure yet/i)).toBeTruthy())
    // The pair to the test above. The whole point of the gate is that the
    // illustrative catalogue's figures never appear under a customer's name, so
    // the invitation must not have quietly become a way to show them.
    expect(container.textContent).not.toMatch(/\$[\d,]/)
  })

  it('states what is already matched, which needs no answers', async () => {
    vi.mocked(dashboard).mockResolvedValue(view({
      ...CRQ_PRICED, detail: { loss_model: { applied: false } },
    }) as never)
    renderPage()
    // Scenario matching runs on the findings, so this count is a fact about the
    // estate rather than about the money — which is exactly why it can be shown
    // when the figure cannot.
    const card = await waitFor(() =>
      screen.getByText(/no loss figure yet/i).closest('div')?.parentElement)
    expect(card?.textContent).toMatch(/318 findings already/)
  })

  it('shows the figure, and not the invitation, once priced', async () => {
    vi.mocked(dashboard).mockResolvedValue(view(CRQ_PRICED) as never)
    renderPage()
    await waitFor(() =>
      expect(screen.getByText(/Annualised loss exposure/)).toBeTruthy())
    expect(screen.queryByText(/no loss figure yet/i)).toBeNull()
  })

  it('says nothing about pricing when the model has not run at all', async () => {
    // No crq row is a different state from an unpriced one: nothing has been
    // computed, so there is no "already matched" count to stand behind and no
    // claim worth making.
    vi.mocked(dashboard).mockResolvedValue(view(null) as never)
    const renderResult = renderPage()
    // Wait on the page having rendered at all, rather than on any string that
    // also appears inside the card under test.
    const { container } = renderResult
    await waitFor(() =>
      expect(container.textContent).not.toContain('Loading'))
    expect(screen.queryByText(/no loss figure yet/i)).toBeNull()
    expect(screen.queryByText(/Annualised loss exposure/)).toBeNull()
  })
})


/* ── the segregation verdict ─────────────────────────────────────────────
 *
 * SODCOV-000 tells the reader to read it before the conflict results. In the
 * offline report it renders above them; here it was one row in a findings list
 * — the same failure fixed there and left standing on this surface.
 */
describe('Dashboard — how far the segregation result can be believed', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    // Same reason as the block above: the CSF and domain strips each fetch and
    // each swallow their own failure, so rejecting them keeps this block about
    // the verdict rather than pinning two unrelated response shapes.
    vi.mocked(csf).mockRejectedValue(new Error('not under test'))
    vi.mocked(compliance).mockRejectedValue(new Error('not under test'))
    vi.mocked(domains).mockRejectedValue(new Error('not under test'))
  })

  function withTrust(trust: unknown) {
    const v = view(null) as Record<string, unknown>
    ;(v.summary as Record<string, unknown>).sod_trust = trust
    return v
  }

  it('shows the verdict and its limits, worst first', async () => {
    vi.mocked(dashboard).mockResolvedValue(
      withTrust({ verdict: 'unbounded', severity: 'HIGH',
                  limits: ['a role grants every transaction',
                           'the ruleset names 0% of the Fiori surface'] }) as never)
    renderPage()
    expect(await screen.findByText(/Segregation of duties: UNBOUNDED/)).toBeTruthy()
    expect(screen.getByText(/a role grants every transaction/)).toBeTruthy()
    expect(screen.getByText(/names 0% of the Fiori surface/)).toBeTruthy()
  })

  it('says so when nothing qualifies the result', async () => {
    vi.mocked(dashboard).mockResolvedValue(
      withTrust({ verdict: 'usable', severity: 'INFO', limits: [] }) as never)
    renderPage()
    expect(await screen.findByText(/No limit was found/)).toBeTruthy()
  })

  it('renders nothing when the check did not run', async () => {
    // A missing verdict is NOT a good one. Defaulting to "usable" here would
    // manufacture the reassurance this whole family of checks exists to refuse.
    vi.mocked(dashboard).mockResolvedValue(view(null) as never)
    renderPage()
    await screen.findAllByText(/318/)   // the count appears in more than one card
    expect(screen.queryByText(/Segregation of duties:/)).toBeNull()
  })
})
