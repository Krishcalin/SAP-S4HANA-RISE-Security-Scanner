import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { Findings } from './Findings'

/**
 * The triage queue's filter row.
 *
 * Seven select controls sit in a row on the screen this product is operated from
 * all day, and every one of them was an unlabelled combo box. A screen reader
 * announced seven consecutive "combo box"es whose only distinguishing text was
 * the currently selected value — so the difference between the severity filter
 * and the team filter was audible only if you had already changed one of them.
 *
 * `tsc` cannot see this. Neither can a human reading the diff, which is why it
 * survived every review the file has had.
 */

vi.mock('../api/client', () => ({
  findings: vi.fn(),
  systems: vi.fn(),
  views: vi.fn(),
  domains: vi.fn(),
  assignFinding: vi.fn(),
  bulkSetState: vi.fn(),
  saveView: vi.fn(),
  ApiError: class ApiError extends Error {
    status: number
    constructor(status: number, message: string) {
      super(message)
      this.status = status
    }
  },
}))

vi.mock('../lib/title', () => ({ useTitle: () => {} }))
vi.mock('../lib/session', () => ({
  useSession: () => ({ user: { username: 't', role: 'analyst', can_write: true } }),
}))

const page = {
  findings: [], total: 0, page: 1, pages: 1,
}

async function renderQueue() {
  const client = await import('../api/client')
  vi.mocked(client.findings).mockResolvedValue(page as never)
  vi.mocked(client.systems).mockResolvedValue([] as never)
  vi.mocked(client.views).mockResolvedValue([] as never)
  vi.mocked(client.domains).mockResolvedValue({
    domains: [{ id: 'identity', label: 'Identity Security', reach: 'full',
                state: 'assessed', total: 3, counts: {}, scope: null, blurb: '',
                categories: [] }],
    unplaced: { counts: {}, total: 0, reasons: {}, note: '' },
    totals: { domains: 12, assessable: 11, findings: 3, placed: 3 },
  } as never)
  render(<MemoryRouter><Findings /></MemoryRouter>)
  await waitFor(() => expect(screen.getByRole('heading', { name: 'Findings' }))
    .toBeInTheDocument())
}

describe('the filter row', () => {
  beforeEach(() => vi.clearAllMocks())

  it('gives every control an accessible name', async () => {
    await renderQueue()
    const unnamed = screen.getAllByRole('combobox')
      .filter((el) => !el.getAttribute('aria-label')
        && !el.getAttribute('aria-labelledby')
        && !el.closest('label'))
    expect(unnamed).toEqual([])
  })

  it('names them distinctly, so two are never announced alike', async () => {
    await renderQueue()
    const names = screen.getAllByRole('combobox')
      .map((el) => el.getAttribute('aria-label'))
    expect(names.length).toBeGreaterThanOrEqual(6)
    expect(new Set(names).size).toBe(names.length)
  })

  it('can be found by what it filters rather than by position', async () => {
    await renderQueue()
    for (const name of [/severity/i, /priority tier/i, /owning team/i,
                        /remediation owner/i, /lifecycle state/i, /SAP system/i]) {
      expect(screen.getByRole('combobox', { name })).toBeInTheDocument()
    }
  })
})

/* ── which rows rest on partial data ───────────────────────────────────────
 *
 * The detail page and the dashboard verdict already carried this. The list did
 * not, so a reader scanning fifty findings had to open each one to learn which
 * conclusions were drawn from a fraction of their module's inputs.
 */
function row(overrides: Record<string, unknown> = {}) {
  return {
    id: 1, check_id: 'USR-001', title: 'Default user SAP* is unlocked',
    severity: 'HIGH', state: 'open', priority_tier: 'P2', priority_score: 40,
    priority_rationale: null, regression_count: 0, assignee: null,
    owning_team: 'identity', default_team: 'identity', category: 'Identity',
    remediation_owner: 'customer_fixable', days_open: 3,
    expired_acceptance: false, is_overdue: false, due_date: null,
    acceptance_due: null, system_label: 'PRD/100', system_tier: 'prod',
    sid: 'PRD', system_client: '100', baseline_req_id: null,
    latest_evidence: null,
    ...overrides,
  }
}

async function renderWith(rows: unknown[]) {
  const client = await import('../api/client')
  vi.mocked(client.findings).mockResolvedValue(
    { findings: rows, total: rows.length, page: 1, pages: 1 } as never)
  vi.mocked(client.systems).mockResolvedValue([] as never)
  vi.mocked(client.views).mockResolvedValue([] as never)
  vi.mocked(client.domains).mockResolvedValue({
    domains: [], unplaced: { counts: {}, total: 0, reasons: {}, note: '' },
    totals: { domains: 12, assessable: 11, findings: 0, placed: 0 },
  } as never)
  render(<MemoryRouter><Findings /></MemoryRouter>)
  await waitFor(() => expect(screen.getByRole('heading', { name: 'Findings' }))
    .toBeInTheDocument())
}

describe('the partial-data marker on the list', () => {
  beforeEach(() => vi.clearAllMocks())

  it('marks a row whose module ran without some of its inputs', async () => {
    await renderWith([row({
      latest_evidence: { complete: false, declared_sources: 3,
                         missing_sources: ['user_groups'] } })])
    expect(await screen.findByText('partial data')).toBeInTheDocument()
  })

  it('names the missing exports where a reader can reach them', async () => {
    await renderWith([row({
      latest_evidence: { complete: false, declared_sources: 3,
                         missing_sources: ['user_groups', 'auth_objects'] } })])
    const marker = await screen.findByText('partial data')
    expect(marker.getAttribute('title')).toContain('user_groups, auth_objects')
  })

  it('leaves a complete row unmarked, because absence already means complete',
     async () => {
    await renderWith([row({
      latest_evidence: { complete: true, declared_sources: 3,
                         missing_sources: [] } })])
    expect(screen.queryByText('partial data')).toBeNull()
  })

  it('leaves a row with no marker at all unmarked', async () => {
    // Findings stored before the column existed carry nothing. Not knowing is
    // a third state and must not render as either answer.
    await renderWith([row()])
    expect(screen.queryByText('partial data')).toBeNull()
  })
})
