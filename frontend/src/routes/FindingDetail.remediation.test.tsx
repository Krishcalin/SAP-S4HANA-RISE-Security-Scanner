/**
 * "The change" on a single finding.
 *
 * THE ONE THING THIS SECTION MUST NEVER DO is print a command for a finding the
 * customer has no right to change. Under RISE most parameters are operated by
 * SAP, and `remediation.pack` says so by answering `applicable: false` with
 * owner `ticket_to_sap` — the page's job is then to render nothing at all,
 * because the ownership is already stated twice above (the banner, and the
 * drafted service request). A third telling would be noise; a `<pre>` block of
 * commands under it would be an instruction to do something the contract does
 * not allow, sitting directly beneath the sentence saying so.
 *
 * THE OTHER REFUSAL IS NOT THE SAME and must not be silenced with it. When the
 * owner IS the customer and the pack still declines — the baseline states a rule
 * rather than a value, or the export does not type the object a grant names —
 * that is new information the reader has nowhere else, and the reason is worth a
 * line. `HANADB-PRIV-006` is the real case: every grant names an untyped object,
 * so a REVOKE would have to guess whether it is a schema, a procedure or a user.
 *
 * Every pack below is `remediation.pack` output on the drive database, not a
 * shape invented here.
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
import type { FindingDetail as Finding, RemediationPack } from '../api/types'

const FINDING = {
  id: 1001,
  landscape_id: 5,
  system_id: null,
  fingerprint: 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6',
  check_id: 'HANADB-PRIV-002',
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
  taint_confidence: null,
  reachability: null,
  title: 'Sweeping HANA system privilege granted to a named user',
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
  remediation: 'Revoke the privilege from the named account.',
  references_json: [],
  responsibility: null,
  cwe: null,
  tier: 'prod',
  deployment_mode: 'rise_pce',
  latest_details: {},
} as unknown as Finding

/** `pack()` on HANADB-PRIV-002 of the drive database, verbatim. */
const APPLICABLE: RemediationPack = {
  kind: 'hana_grant',
  applicable: true,
  owner: 'customer_fixable',
  where: 'HANA SQL console — PRD',
  executable: true,
  apply: [
    'REVOKE DATA ADMIN FROM J_SMITH;',
    'REVOKE USER ADMIN FROM SVC_INTERFACE;',
  ],
  rollback: [
    'GRANT DATA ADMIN TO J_SMITH;',
    'GRANT USER ADMIN TO SVC_INTERFACE;',
  ],
  verify: 'Re-run the scan; HANADB-PRIV-002 closes when these grants are gone.',
  source: '',
  caveats: [
    'Review and apply through your normal change control. This tool holds no ' +
    'connection to SAP and has changed nothing.',
    'Run as a user holding the privilege WITH ADMIN OPTION; a REVOKE of a ' +
    'grantable privilege cascades to anything the grantee granted onward.',
  ],
}

/** `pack()` on HANADB-PRIV-006: the customer's to fix, and still undecidable. */
const DECLINED_BUT_OURS: RemediationPack = {
  kind: 'hana_grant',
  applicable: false,
  owner: 'customer_fixable',
  why: 'every grant here names an object the export does not type, so the ' +
       'REVOKE would have to guess whether it is a schema, a procedure or a user',
  apply: [],
  rollback: [],
}

/** `pack()` on PARAM-LOGIN/MIN_PASSWORD_LNG under RISE: SAP's to operate. */
const SAP_OWNED: RemediationPack = {
  kind: 'profile_parameter',
  applicable: false,
  owner: 'ticket_to_sap',
  why: 'this parameter is operated by SAP under the contract; raise the ' +
       'drafted service request instead',
  apply: [],
  rollback: [],
}

async function draw(pack?: RemediationPack) {
  finding.mockResolvedValue({
    ...(FINDING as unknown as Record<string, unknown>),
    remediation_pack: pack,
  })
  findingHistory.mockResolvedValue({ history: [], observations: [] })
  serviceRequest.mockResolvedValue({})
  render(<MemoryRouter><FindingDetail /></MemoryRouter>)
  await screen.findByText('Sweeping HANA system privilege granted to a named user')
}

function body(): string { return document.body.textContent ?? '' }

/** The card under the "The change" heading, so an assertion about this section
 *  cannot be satisfied — or defeated — by markup belonging to another one. */
function changeCard(): HTMLElement {
  const h2 = screen.getByText('The change')
  const card = h2.nextElementSibling
  if (!(card instanceof HTMLElement)) {
    throw new Error('the "The change" heading has no card after it')
  }
  return card
}

beforeEach(() => { vi.clearAllMocks() })

describe('a change the customer can make', () => {
  it('prints the statements to run', async () => {
    await draw(APPLICABLE)
    expect(screen.getByText('The change')).toBeTruthy()
    expect(body()).toContain('REVOKE DATA ADMIN FROM J_SMITH;')
    expect(body()).toContain('REVOKE USER ADMIN FROM SVC_INTERFACE;')
  })

  it('prints the rollback beside it', async () => {
    await draw(APPLICABLE)
    expect(screen.getByText('Roll back')).toBeTruthy()
    expect(body()).toContain('GRANT DATA ADMIN TO J_SMITH;')
  })

  it('says where the statements run', async () => {
    await draw(APPLICABLE)
    expect(body()).toContain('HANA SQL console')
  })

  it('says how to confirm it worked', async () => {
    await draw(APPLICABLE)
    expect(body()).toMatch(/Re-run the scan/)
  })

  it('carries the caveats, including that nothing was applied', async () => {
    await draw(APPLICABLE)
    // The product holds no connection to SAP. A page of REVOKE statements with
    // no such line reads as a record of work done.
    expect(body()).toMatch(/has changed nothing/)
    expect(body()).toContain('WITH ADMIN OPTION')
  })
})

describe('a change that cannot be written', () => {
  it('gives the reason when the finding is still the customer to fix', async () => {
    await draw(DECLINED_BUT_OURS)
    expect(screen.getByText('The change')).toBeTruthy()
    // New information: nothing else on the page says why there is no command.
    expect(body()).toMatch(/does not type/)
  })

  it('prints no commands with it', async () => {
    await draw(DECLINED_BUT_OURS)
    // Not asserted as "the word REVOKE is absent": the REASON says the word —
    // "the REVOKE would have to guess whether it is a schema" — and a test that
    // banned it would fail on the very sentence it exists to keep.
    //
    // Nor across the whole document: the drafted service request further down
    // has a <pre> of its own, so a page-wide count is 1 whatever this section
    // renders.
    expect(changeCard().querySelectorAll('pre').length).toBe(0)
    expect(screen.queryByText('Roll back')).toBeNull()
  })
})

describe('a finding SAP operates', () => {
  it('renders no change section at all', async () => {
    await draw(SAP_OWNED)
    // The banner and the drafted service request already say who owns it; this
    // section would be the third telling.
    expect(screen.queryByText('The change')).toBeNull()
  })

  it('never prints a command under it', async () => {
    await draw(SAP_OWNED)
    const text = body()
    expect(text).not.toContain('REVOKE')
    expect(text).not.toMatch(/^\s*Apply\s*$/m)
  })
})

describe('a finding with no pack', () => {
  it('renders nothing rather than an empty card', async () => {
    await draw(undefined)
    expect(screen.queryByText('The change')).toBeNull()
  })
})
