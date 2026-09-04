/**
 * Why a finding ranks where it does.
 *
 * `priority_factors` has been stored as jsonb since the prioritiser landed, and
 * its own type comment says it is "kept as data so a screen can show WHY a
 * finding ranks where it does. Explainability is the product." No screen showed
 * it: the tier was a bare badge with the rationale hidden in a title attribute
 * on the list. A tier nobody can interrogate is the confident-number-without-a-
 * reason this product objects to in other people's tools.
 */
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const finding = vi.fn()
const findingHistory = vi.fn()
const serviceRequest = vi.fn()

vi.mock('../api/client', () => ({
  finding: (...a: unknown[]) => finding(...a),
  findingHistory: (...a: unknown[]) => findingHistory(...a),
  serviceRequest: (...a: unknown[]) => serviceRequest(...a),
  setFindingState: vi.fn(),
  assignFinding: vi.fn(),
  ApiError: class ApiError extends Error {
    status: number
    constructor(status: number, message: string) { super(message); this.status = status }
  },
}))
vi.mock('../lib/title', () => ({ useTitle: () => {} }))
vi.mock('../lib/session', () => ({
  useSession: () => ({ user: { username: 't', role: 'admin', can_write: true } }),
}))
vi.mock('react-router', async () => {
  const actual = await vi.importActual<typeof import('react-router')>('react-router')
  return { ...actual, useParams: () => ({ id: '1' }) }
})

import { FindingDetail } from './FindingDetail'
import type { FindingDetail as Finding } from '../api/types'

const BASE = {
  id: 1, landscape_id: 5, system_id: null, fingerprint: 'a'.repeat(32),
  check_id: 'USR-002', client: '100', fingerprint_basis: 'objects',
  scope: 'aggregate', subject: [], severity: 'CRITICAL',
  priority_tier: 'P1', priority_score: 89, priority_factors: [],
  priority_rationale: null, state: 'open', remediation_owner: 'customer',
  assignee: null, owning_team: null, due_date: null, provider_ticket_ref: null,
  first_seen_run: null, last_seen_run: null,
  first_seen_at: '2026-09-01T00:00:00Z', last_detected_at: '2026-09-01T00:00:00Z',
  resolved_at: null, regression_count: 0, accepted_by: null,
  acceptance_reason: null, acceptance_from: null, acceptance_due: null,
  false_positive_reason: null, transitioned_by: null, last_transition_at: null,
  sla_started_at: null, taint_confidence: null, reachability: null,
  title: 'Users assigned critical profiles', category: 'User & Authorization',
  default_team: null, baseline_req_id: null, sid: 'PRD', system_client: '100',
  system_tier: null, platform: null, external_key: null, system_label: null,
  expired_acceptance: false, is_overdue: false, days_open: 0,
  latest_evidence: null, risk_narrative: null, remediation: null,
  references_json: [], responsibility: null, cwe: null, tier: 'prod',
  deployment_mode: 'rise_pce', latest_details: {},
} as unknown as Finding

async function draw(factors: unknown[], over: Record<string, unknown> = {}) {
  finding.mockResolvedValue({ ...BASE, priority_factors: factors, ...over })
  findingHistory.mockResolvedValue({ history: [], observations: [] })
  serviceRequest.mockResolvedValue({})
  render(<MemoryRouter><FindingDetail /></MemoryRouter>)
  await screen.findByText('Users assigned critical profiles')
}

const FACTORS = [
  { label: 'Severity CRITICAL', detail: 'base risk from the finding severity',
    points: 55 },
  { label: 'Known privileged path',
    detail: 'default credentials / critical authorization / trust abuse',
    points: 14 },
  { label: 'Account in use',
    detail: 'the account this is about logged on in the exported window — '
          + 'JSMITH, MWILSON logged on in the exported window',
    points: 10 },
]

beforeEach(() => { vi.clearAllMocks() })

describe('why this ranks where it does', () => {
  it('names the tier it is explaining', async () => {
    await draw(FACTORS)
    expect(screen.getByText('Why this is P1')).toBeInTheDocument()
  })

  it('lists every factor with its reason', async () => {
    await draw(FACTORS)
    expect(screen.getByText('Known privileged path')).toBeInTheDocument()
    expect(screen.getByText(/base risk from the finding severity/))
      .toBeInTheDocument()
  })

  it('shows the points, because their size is the argument', async () => {
    // "+25 actively exploited" beside "+10 account in use" says which evidence
    // did the work; a list of labels alone does not.
    await draw(FACTORS)
    expect(screen.getByText('+55')).toBeInTheDocument()
    expect(screen.getByText('+10')).toBeInTheDocument()
  })

  it('shows the score the factors add up to', async () => {
    await draw(FACTORS)
    expect(screen.getByText('89')).toBeInTheDocument()
  })

  it('surfaces the activity evidence a reader can act on', async () => {
    // The whole point of the activity work: not "this is P1" but "this is P1
    // because the account is one somebody logs on as".
    await draw(FACTORS)
    expect(screen.getByText(/JSMITH, MWILSON logged on in the exported window/))
      .toBeInTheDocument()
  })

  it('omits the section when the prioritiser produced nothing', async () => {
    await draw([])
    expect(screen.queryByText(/^Why this is/)).toBeNull()
  })
})
