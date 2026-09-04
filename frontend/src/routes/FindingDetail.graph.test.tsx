/**
 * "Related by configuration" on a finding.
 *
 * THE CLAIM THIS SECTION MUST NOT MAKE. `data/graph_edges.json` says it
 * outright: AUTH-002 evidences user→role and role→auth_object, and does NOT
 * evidence user→auth_object — that is the transitive closure, and asserting it
 * would state as observed what is only implied. This data invites exactly that
 * mistake, because the two hops sit next to each other on the screen and the
 * sentence "JSMITH has S_RFCACL" writes itself.
 *
 * So the rows are single steps, never joined, and the page says why.
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

const FINDING = {
  id: 1001,
  landscape_id: 5,
  system_id: null,
  fingerprint: 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6',
  check_id: 'PARAM-LOGIN/MIN_PASSWORD_LNG',
  client: '100',
  fingerprint_basis: 'objects',
  scope: 'object',
  subject: [],
  severity: 'HIGH',
  priority_tier: null,
  priority_score: null,
  priority_factors: [],
  priority_rationale: null,
  state: 'open',
  remediation_owner: 'ticket_to_sap',
  assignee: null,
  owning_team: null,
  due_date: null,
  provider_ticket_ref: null,
  first_seen_run: null,
  last_seen_run: null,
  first_seen_at: '2026-09-01T00:00:00Z',
  last_detected_at: '2026-09-01T00:00:00Z',
  resolved_at: null,
  regression_count: 0,
  accepted_by: null,
  acceptance_reason: null,
  acceptance_from: null,
  acceptance_due: null,
  false_positive_reason: null,
  transitioned_by: null,
  last_transition_at: null,
  sla_started_at: null,
  taint_confidence: null,
  reachability: null,
  title: 'Password minimum length below the ECS baseline',
  category: null,
  default_team: null,
  baseline_req_id: null,
  sid: 'PRD',
  system_client: null,
  system_tier: null,
  platform: null,
  external_key: null,
  system_label: null,
  expired_acceptance: false,
  is_overdue: false,
  days_open: 0,
  latest_evidence: null,
  // FindingDetail's own additions, on top of the row above.
  risk_narrative: null,
  remediation: 'Set login/min_password_lng to at least the mandated minimum.',
  references_json: [],
  responsibility: null,
  cwe: null,
  tier: 'prod',
  deployment_mode: 'rise_pce',
  latest_details: {},
} as unknown as Finding


function base(graph: unknown) {
  return { ...(FINDING as unknown as Record<string, unknown>), graph }
}

async function draw(graph: unknown) {
  finding.mockResolvedValue(base(graph))
  findingHistory.mockResolvedValue({ history: [], observations: [] })
  serviceRequest.mockResolvedValue({})
  render(<MemoryRouter><FindingDetail /></MemoryRouter>)
  await screen.findByText('Password minimum length below the ECS baseline')
}

const EDGES = {
  held_by: [{ name: 'JSMITH', type: 'user', object: 'Z_BASIS_SUPER',
              object_type: 'role', edge_type: 'holds_role',
              provenance: 'configured', check_id: 'AUTH-002' }],
  grants: [{ name: 'S_RFCACL', type: 'auth_object', object: 'Z_BASIS_SUPER',
             object_type: 'role', edge_type: 'grants_authorization',
             provenance: 'configured', check_id: 'AUTH-002' }],
  within: [],
  objects: 1,
  edges_available: 67,
}

beforeEach(() => { vi.clearAllMocks() })

describe('related by configuration', () => {
  it('shows who holds the role and what the role grants', async () => {
    await draw(EDGES)
    expect(screen.getByText('JSMITH')).toBeInTheDocument()
    expect(screen.getByText('S_RFCACL')).toBeInTheDocument()
    expect(screen.getAllByText('Z_BASIS_SUPER').length).toBeGreaterThan(0)
  })

  it('says the steps are not to be joined together', async () => {
    // The one sentence that stops a reader drawing the transitive conclusion.
    await draw(EDGES)
    expect(screen.getByText(/do not evidence that the holder has the authorisation/))
      .toBeInTheDocument()
  })

  it('never renders the transitive claim itself', async () => {
    await draw(EDGES)
    const text = document.body.textContent || ''
    // "JSMITH ... S_RFCACL" must never appear as one statement.
    expect(text).not.toMatch(/JSMITH\s*(has|holds|can use)\s*S_RFCACL/i)
  })

  it('omits the section when the graph joins nothing', async () => {
    await draw({ held_by: [], grants: [], within: [], objects: 3,
                 edges_available: 67 })
    expect(screen.queryByText('Related by configuration')).toBeNull()
  })

  it('omits the section entirely on an older server', async () => {
    await draw(undefined)
    expect(screen.queryByText('Related by configuration')).toBeNull()
  })

  it('renders an edge the finding owns both ends of, once', async () => {
    await draw({
      held_by: [], grants: [],
      within: [{ from: 'JSMITH', from_type: 'user', to: 'SAP_ALL',
                 to_type: 'profile', edge_type: 'holds_profile',
                 provenance: 'used', check_id: 'USR-002' }],
      objects: 8, edges_available: 67,
    })
    expect(screen.getAllByText('JSMITH')).toHaveLength(1)
    expect(screen.getAllByText('SAP_ALL')).toHaveLength(1)
  })
})
