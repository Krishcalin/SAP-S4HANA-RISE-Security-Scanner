/**
 * "Reachable from outside" on a code finding.
 *
 * THE DISTINCTION THIS SCREEN WAS COLLAPSING. "Reachable" above it means
 * something in the system references the object — it separates live code from
 * housekeeping and says nothing about the network. An SQL injection in a class
 * published on an unauthenticated ICF node and the same statement in a class
 * only a nightly job touches rendered identically.
 *
 * THREE STATES, AND NULL IS THE COMMON ONE. The backend sets `internet_exposed`
 * to null wherever it found no route, because a dynamic call resolves to no
 * edge and the entry list is only as complete as the HANDLER_CLASS / IMPL_CLASS
 * columns the customer exported. Rendering null as "not exposed" would tell
 * somebody their injection is unreachable on the strength of what we could not
 * see — so the null case must say what is missing and claim nothing.
 *
 * And the route is shown, not just the verdict. A customer who cannot check the
 * claim will not act on it.
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

/** modules/abap_sast.py on tests/fixtures/abap_tree with the two columns
 *  supplied: the injection two calls in from an unauthenticated ICF node. */
const EXPOSED_DETAILS = {
  source: 'abap_scan',
  confidence: 'confirmed',
  internet_exposed: true,
  exposure_reasons: [
    'reached from ZCL_TREE_CALLER, 2 call(s) in',
    'ICF /sap/bc/z_vendor_report is published with no authentication',
  ],
  exposure_path: [
    { from: 'zcl_tree_caller~drive', to: 'zcl_tree_worker~entry',
      file: 'zcl_tree_caller.clas.abap', line: 25, code: '' },
    { from: 'zcl_tree_worker~entry', to: 'zcl_tree_worker~priv_tainted',
      file: 'zcl_tree_worker.clas.abap', line: 32, code: '' },
  ],
}

const UNKNOWN_DETAILS = {
  source: 'abap_scan',
  confidence: 'confirmed',
  internet_exposed: null,
  exposure_reasons: ['no HANDLER_CLASS or IMPL_CLASS column was supplied'],
}

const FINDING = {
  id: 1001,
  landscape_id: 5,
  system_id: null,
  fingerprint: 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6',
  check_id: 'ABAP-SQLI-001',
  client: '100',
  fingerprint_basis: 'objects',
  scope: 'object',
  subject: [],
  severity: 'CRITICAL',
  priority_tier: null,
  priority_score: null,
  priority_factors: [],
  priority_rationale: null,
  state: 'open',
  remediation_owner: 'customer_fixable',
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
  taint_confidence: 'confirmed',
  reachability: 'reachable',
  title: 'Dynamic WHERE clause built from caller input',
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
  risk_narrative: null,
  remediation: null,
  references_json: [],
  responsibility: null,
  cwe: 'CWE-89',
  tier: 'prod',
  deployment_mode: 'rise_pce',
  latest_details: {},
} as unknown as Finding

async function draw(details: Record<string, unknown> | null) {
  finding.mockResolvedValue({
    ...(FINDING as unknown as Record<string, unknown>),
    latest_details: details ?? { source: 'abap_scan' },
  })
  findingHistory.mockResolvedValue({ history: [], observations: [] })
  serviceRequest.mockResolvedValue({})
  render(<MemoryRouter><FindingDetail /></MemoryRouter>)
  await screen.findByText('Dynamic WHERE clause built from caller input')
}

/** The <dd> belonging to a <dt>, so an assertion about this row cannot be
 *  satisfied — or defeated — by another row that happens to say the same word.
 *  "unknown" appears more than once on this page. */
function valueFor(label: string): HTMLElement {
  const dt = screen.getByText(label)
  const dd = dt.nextElementSibling
  if (!(dd instanceof HTMLElement)) throw new Error('no value cell for ' + label)
  return dd
}

beforeEach(() => { vi.clearAllMocks() })

describe('reachable from outside', () => {
  it('says so, and names the endpoint', async () => {
    await draw(EXPOSED_DETAILS)
    expect(screen.getByText('Reachable from outside')).toBeTruthy()
    expect(valueFor('Reachable from outside').textContent)
      .toContain('published endpoint')
    expect(document.body.textContent).toContain('/sap/bc/z_vendor_report')
    expect(document.body.textContent).toContain('no authentication')
  })

  it('shows the route, so the claim can be checked', async () => {
    await draw(EXPOSED_DETAILS)
    const text = document.body.textContent ?? ''
    expect(text).toContain('zcl_tree_caller~drive')
    expect(text).toContain('zcl_tree_worker~priv_tainted')
    expect(text).toContain('zcl_tree_caller.clas.abap')
  })

  it('keeps it separate from "Reachable"', async () => {
    await draw(EXPOSED_DETAILS)
    // Both are shown, because they answer different questions: one is "is this
    // code live", the other is "can somebody on the network get to it".
    expect(screen.getByText('Reachable')).toBeTruthy()
    expect(screen.getByText('Reachable from outside')).toBeTruthy()
  })

  it('never renders an unknown exposure as safe', async () => {
    await draw(UNKNOWN_DETAILS)
    const cell = valueFor('Reachable from outside')
    expect(cell.textContent).toContain('unknown')
    const text = document.body.textContent ?? ''
    expect(text).not.toContain('not exposed')
    expect(text).not.toContain('no path found from outside')
  })

  it('says what is missing when it could not tell', async () => {
    await draw(UNKNOWN_DETAILS)
    expect(document.body.textContent).toContain('HANDLER_CLASS')
  })

  it('renders no row at all for a finding that is not code', async () => {
    await draw({ source: 'config_scan' })
    expect(screen.queryByText('Reachable from outside')).toBeNull()
  })

  it('renders no row for a code finding the join never ran on', async () => {
    // An ATC import is a code finding — it passes the `isCode` gate that wraps
    // this whole panel — and it never goes through the exposure join, so it
    // carries no `internet_exposed` key at all. Rendering "unknown" for it would
    // invite the reader to supply columns that would not change its answer.
    await draw({ source: 'atc_export', confidence: 'pattern-only' })
    expect(screen.queryByText('Reachable from outside')).toBeNull()
  })
})
