/**
 * The service-request panel on the finding page.
 *
 * THE DEFECT THIS COVERS was a sentence the code did not keep. The page told
 * the customer, for every finding SAP operates:
 *
 *     Raise a service request rather than attempting the change — the
 *     pre-drafted text is below.
 *
 * There was none. What was below was the check's generic remediation, which
 * for a profile parameter opens "Set login/min_password_lng to at least the
 * mandated minimum" — the instruction the sentence above it had just said the
 * customer could not carry out.
 *
 * Only the panel is exercised here. The page had no test file at all, which is
 * why adding a fetch to it broke nothing; a fixture covering the whole of it is
 * a larger job than this defect, and covering the whole page badly would be a
 * worse use of the effort than covering this part properly.
 */
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const finding = vi.fn()
const findingHistory = vi.fn()
const serviceRequest = vi.fn()

vi.mock('../api/client', () => ({
  finding: (...a: unknown[]) => finding(...a),
  findingHistory: (...a: unknown[]) => findingHistory(...a),
  serviceRequest: (...a: unknown[]) => serviceRequest(...a),
  assignFinding: vi.fn(),
  setFindingState: vi.fn(),
  ApiError: class ApiError extends Error {
    status: number
    constructor(status: number, message: string) { super(message); this.status = status }
  },
}))
vi.mock('../lib/title', () => ({ useTitle: () => {} }))
vi.mock('../lib/session', () => ({
  useSession: () => ({ user: { username: 't', role: 'analyst',
                               can_write: true } }),
}))

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

const DRAFT = {
  finding_id: 1001, check_id: FINDING.check_id, system: 'PRD',
  setting: 'login/min_password_lng', has_values: true,
  provider_ticket_ref: null,
  text: 'Subject: RISE with SAP, Private Cloud Edition configuration request\n'
      + '\nSystem:   PRD client 100\nSetting:  login/min_password_lng\n'
      + 'Current:  6\nRequired: 15\n\nPlease set login/min_password_lng to 15 on PRD.',
}

function draw() {
  return render(
    <MemoryRouter initialEntries={['/findings/1001']}>
      <Routes>
        <Route path="/findings/:id" element={<FindingDetail />} />
      </Routes>
    </MemoryRouter>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  finding.mockResolvedValue(FINDING)
  findingHistory.mockResolvedValue({ history: [], observations: [] })
  serviceRequest.mockResolvedValue(DRAFT)
})

describe('the service request the page promises', () => {
  it('shows the drafted text, not an instruction to make the change', async () => {
    draw()
    expect(await screen.findByText(/Service request to SAP/)).toBeInTheDocument()
    expect(screen.getByText(/Please set login\/min_password_lng to 15 on PRD/))
      .toBeInTheDocument()
  })

  it('says the draft asks a question when the values were not readable', async () => {
    serviceRequest.mockResolvedValue({
      ...DRAFT, has_values: false,
      text: 'Please confirm the current value of login/other on PRD.',
    })
    draw()
    expect(await screen.findByText(/asks\s+SAP to confirm it rather than stating a change/))
      .toBeInTheDocument()
  })

  it('draws no box at all for a finding the customer can fix', async () => {
    // The endpoint 404s for those, and an empty panel headed "Service request
    // to SAP" on a finding nobody needs to raise is worse than no panel.
    serviceRequest.mockRejectedValue(new Error('not found'))
    draw()
    await screen.findByText(FINDING.title)
    await waitFor(() => {
      expect(screen.queryByText(/Service request to SAP/)).not.toBeInTheDocument()
    })
  })
})
