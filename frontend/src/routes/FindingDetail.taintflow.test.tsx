/**
 * "How untrusted input reaches it" — the taint trace on a code finding.
 *
 * THE STEP THAT CAN LIE. Since the ABAP call graph spans the scanned tree, the
 * call that feeds a method's parameter is usually in ANOTHER artefact: a class's
 * callers live in other files by construction. The backend marks such a step
 * with the file it came from.
 *
 * Rendered as line/role/var/statement alone, that step reads "line 20" — and the
 * reader looks at line 20 of the file they are already looking at, which is an
 * unrelated statement about something else. The row would be pointing at the
 * wrong code while looking exactly as authoritative as the rows around it.
 *
 * A step with no `file` is in the finding's own artefact, and must stay clean:
 * most traces in the product are entirely local, and stamping a filename on
 * every row of those is noise.
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

/** modules/abap_sast.py on tests/fixtures/abap_tree, verbatim: the SQL injection
 *  in zcl_tree_worker~by_public_tainted, whose caller is in the other file. */
const FLOW = [
  {
    line: 20,
    role: 'call',
    var: 'iv_user_input',
    code: 'lo_worker->by_public_tainted( iv_where = iv_user_input )',
    file: 'zcl_tree_caller.clas.abap',
  },
  { line: 35, role: 'source', var: 'iv_where', code: 'METHOD by_public_tainted' },
  {
    line: 36,
    role: 'sink',
    var: 'iv_where',
    code: 'SELECT * FROM sflight INTO TABLE @DATA(lt_a) WHERE (iv_where)',
  },
]

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
  reachability: null,
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

async function draw(flow: unknown) {
  finding.mockResolvedValue({
    ...(FINDING as unknown as Record<string, unknown>),
    latest_details: { source: 'abap_scan', taint_flow: flow, confidence: 'confirmed' },
  })
  findingHistory.mockResolvedValue({ history: [], observations: [] })
  serviceRequest.mockResolvedValue({})
  render(<MemoryRouter><FindingDetail /></MemoryRouter>)
  await screen.findByText('Dynamic WHERE clause built from caller input')
}

/** The row a step renders into, found by its statement text. */
function rowFor(code: string): HTMLElement {
  const cell = screen.getByText(code)
  const row = cell.closest('tr')
  if (!row) throw new Error('no row for ' + code)
  return row as HTMLElement
}

beforeEach(() => { vi.clearAllMocks() })

describe('the taint trace', () => {
  it('renders every step', async () => {
    await draw(FLOW)
    expect(screen.getByText(/How untrusted input reaches it/)).toBeTruthy()
    expect(screen.getByText('METHOD by_public_tainted')).toBeTruthy()
    expect(screen.getByText(/lo_worker->by_public_tainted/)).toBeTruthy()
  })

  it('names the artefact a cross-file step came from', async () => {
    await draw(FLOW)
    const row = rowFor('lo_worker->by_public_tainted( iv_where = iv_user_input )')
    expect(row.textContent).toContain('zcl_tree_caller.clas.abap')
    expect(row.textContent).toContain('20')
  })

  it('leaves a step in the finding’s own file unmarked', async () => {
    await draw(FLOW)
    const row = rowFor('METHOD by_public_tainted')
    expect(row.textContent).not.toContain('.clas.abap')
    expect(row.textContent).not.toContain('.prog.abap')
  })

  it('shows the variable the caller actually passed', async () => {
    await draw(FLOW)
    const row = rowFor('lo_worker->by_public_tainted( iv_where = iv_user_input )')
    // `iv_user_input`, not `iv_where`: the callee's parameter name is not on
    // the caller's line, and naming it there sends the reader looking for a
    // variable that is not in the statement they are shown.
    expect(row.textContent).toContain('iv_user_input')
  })

  it('renders a wholly local trace without any filename', async () => {
    await draw(FLOW.slice(1))
    const table = screen.getByText('METHOD by_public_tainted').closest('table')
    expect(table?.textContent ?? '').not.toContain('.abap')
  })

  it('renders nothing when there is no trace', async () => {
    await draw([])
    expect(screen.queryByText(/How untrusted input reaches it/)).toBeNull()
  })
})
