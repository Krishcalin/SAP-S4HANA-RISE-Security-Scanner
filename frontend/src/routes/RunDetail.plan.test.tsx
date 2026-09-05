/**
 * "What to change on <SID>" — the change plan on the run page.
 *
 * TWO THINGS THIS SECTION CAN GET WRONG, and both of them read as good news.
 *
 * The first is arithmetic. `plan_for_system` on the drive data answers 8 changes
 * out of 405 open findings: one block of HANA REVOKEs, 36 findings SAP operates
 * under the contract, 1 declined because the export does not type the object,
 * and 363 it cannot write a change for at all. Eight changes shown alone reads
 * as a remedy for the system. Eight shown beside 363 reads as what it is. So the
 * "Not in this plan" line is not a footnote — it is the only thing that stops
 * the section overstating itself, and it is asserted here on its own.
 *
 * The second is timing. This screen already refuses to fetch the run diff until
 * the run is terminal, because findings land in one transaction and "New 0" over
 * an unfinished scan reads as "clean". A plan is the same claim in a different
 * shape: built mid-scan it is a change list for a system whose findings are
 * still being written, and it would shrink as the scan progressed.
 *
 * Both are pinned below against mutation, not against the current markup.
 */
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const run = vi.fn()
const runDiff = vi.fn()
const remediationPlan = vi.fn()

vi.mock('../api/client', () => ({
  run: (...a: unknown[]) => run(...a),
  runDiff: (...a: unknown[]) => runDiff(...a),
  remediationPlan: (...a: unknown[]) => remediationPlan(...a),
  runExportValue: () => Promise.reject(new Error('not this test')),
  cancelRun: vi.fn(),
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
  return { ...actual, useParams: () => ({ id: '7' }) }
})

import { RunDetail } from './RunDetail'
import type { RemediationPlan, RunStatus, ScanRun } from '../api/types'

const RUN: ScanRun = {
  id: 7,
  landscape_id: 3,
  system_id: 1,
  status: 'complete',
  content_sha: null,
  uploaded_by: 't',
  upload_name: 'prd.zip',
  started_at: '2026-09-01T09:00:00+00:00',
  finished_at: '2026-09-01T09:04:00+00:00',
  progress_done: 23,
  progress_total: 23,
  cancel_requested: false,
  error: null,
  coverage: {},
  module_status: {},
  scanner_version: '1.0.0',
  sid: 'PRD',
  client: '100',
  platform: 'abap',
  external_key: null,
  system_label: 'PRD',
} as unknown as ScanRun

/** server/remediation.py:plan_for_system, system 1 of the drive database,
 *  trimmed to three grants. Counts are the real ones. */
const PLAN: RemediationPlan = {
  system_id: 1,
  sid: 'PRD',
  findings_considered: 405,
  blocks: [{
    kind: 'hana_grant',
    where: 'HANA SQL console — PRD',
    executable: true,
    apply: [
      'REVOKE DATA ADMIN FROM J_SMITH;',
      'REVOKE USER ADMIN FROM SVC_INTERFACE;',
      'REVOKE TRACE ADMIN FROM CONTRACTOR1;',
    ],
    rollback: [
      'GRANT TRACE ADMIN TO CONTRACTOR1;',
      'GRANT USER ADMIN TO SVC_INTERFACE;',
      'GRANT DATA ADMIN TO J_SMITH;',
    ],
    closes: ['HANADB-PRIV-002', 'HANADB-PRIV-003', 'HANADB-ROLE-001'],
    caveats: [
      'Review and apply through your normal change control. This tool holds ' +
      'no connection to SAP and has changed nothing.',
      'Run as a user holding the privilege WITH ADMIN OPTION; a REVOKE of a ' +
      'grantable privilege cascades to anything the grantee granted onward.',
    ],
  }],
  changes: 8,
  sap_owned: 36,
  declined: [{
    check_id: 'HANADB-PRIV-006',
    why: 'every grant here names an object the export does not type',
  }],
  not_covered: 363,
}

function show(status: RunStatus = 'complete', plan: RemediationPlan | null = PLAN) {
  run.mockResolvedValue({ ...RUN, status })
  runDiff.mockResolvedValue(null)
  remediationPlan.mockImplementation(
    () => plan ? Promise.resolve(plan) : Promise.reject(new Error('404')))
  return render(<MemoryRouter><RunDetail /></MemoryRouter>)
}

/** The whole page as one string, so an assertion cannot be satisfied by text
 *  that happens to sit in a different section. */
function body(): string {
  return document.body.textContent ?? ''
}

/** RunDetail's own PHASE map, copied rather than imported — it is not exported,
 *  and a copy that drifts fails these tests loudly instead of silently making
 *  them wait on text that never appears. Used only as proof that a poll has
 *  landed and re-rendered. */
const PHASE_TEXT: Partial<Record<RunStatus, string>> = {
  pending: 'Queued. The scan starts when a worker picks the bundle up.',
  parsing: 'Reading the uploaded export files.',
  scanning: 'Running the audit modules.',
  deriving: 'Deriving risk paths, financial risk and the run-over-run diff.',
}

beforeEach(() => { vi.clearAllMocks() })

describe('the change plan on a finished run', () => {
  it('shows the commands to apply', async () => {
    show()
    await waitFor(() => expect(screen.getByText(/What to change on PRD/)).toBeTruthy())
    expect(body()).toContain('REVOKE DATA ADMIN FROM J_SMITH;')
    expect(body()).toContain('REVOKE TRACE ADMIN FROM CONTRACTOR1;')
  })

  it('shows the rollback, and keeps it separate from the apply', async () => {
    show()
    await waitFor(() => expect(screen.getByText(/Roll back, in this order/)).toBeTruthy())
    // Reversed relative to apply: revoking A then B rolls back as B then A, and
    // a rollback pasted in apply order re-grants in the wrong sequence.
    const text = body()
    expect(text.indexOf('GRANT TRACE ADMIN TO CONTRACTOR1;'))
      .toBeLessThan(text.indexOf('GRANT DATA ADMIN TO J_SMITH;'))
  })

  it('says where the block runs and what it closes', async () => {
    show()
    await waitFor(() => expect(screen.getByText(/HANA SQL console/)).toBeTruthy())
    expect(body()).toMatch(/closes 3 check/)
  })

  it('carries the caveats', async () => {
    show()
    await waitFor(() => expect(body()).toContain('WITH ADMIN OPTION'))
    expect(body()).toContain('has changed nothing')
  })

  // ── the honesty of the counts ──────────────────────────────────────────────

  it('states what the plan does NOT cover, beside what it does', async () => {
    show()
    await waitFor(() => expect(screen.getByText(/Not in this plan/)).toBeTruthy())
    const text = body()
    expect(text).toContain('36')   // SAP operates these
    expect(text).toContain('363')  // no change this tool can write
    expect(text).toMatch(/1 where the baseline states a rule/)  // declined
  })

  it('never presents the changes as the whole of the system', async () => {
    show()
    await waitFor(() => expect(screen.getByText(/Not in this plan/)).toBeTruthy())
    // 405 findings considered is on the page with the 8 changes. Without it the
    // section is eight commands and no denominator.
    expect(body()).toMatch(/405 open finding/)
  })

  it('says nothing has been applied', async () => {
    show()
    await waitFor(() => expect(screen.getByText(/What to change on PRD/)).toBeTruthy())
    expect(body()).toMatch(/nothing here has been applied/)
  })

  // ── when there is no plan ──────────────────────────────────────────────────

  it('renders no heading when the system has nothing to change', async () => {
    show('complete', null)
    await waitFor(() => expect(remediationPlan).toHaveBeenCalled())
    expect(screen.queryByText(/What to change/)).toBeNull()
  })

  it('renders no heading when the plan came back with zero changes', async () => {
    show('complete', { ...PLAN, changes: 0, blocks: [] })
    await waitFor(() => expect(remediationPlan).toHaveBeenCalled())
    // An empty "What to change on PRD" over no commands reads as "nothing to
    // change", which is not what a zero-change plan means — it means nothing
    // here is customer-fixable.
    expect(screen.queryByText(/What to change/)).toBeNull()
  })

  // ── timing ────────────────────────────────────────────────────────────────

  it.each(['pending', 'parsing', 'scanning', 'deriving'] as RunStatus[])(
    'does not ask for a plan while the run is %s', async (status) => {
      show(status)
      // WAIT FOR THE POLL TO HAVE LANDED AND RENDERED, not merely to have been
      // called. `systemId` is read off the fetched row, so before the first poll
      // resolves it is null and the effect returns early whatever the status is
      // — an assertion made at that moment passes with the status guard deleted,
      // which is how this test read until a mutation ran against it. The phase
      // text renders only once `poll` is set, so it is proof the guard, and not
      // the clock, is what stopped the request.
      await screen.findByText(PHASE_TEXT[status]!)
      await Promise.resolve()
      expect(remediationPlan).not.toHaveBeenCalled()
    })

  it.each(['complete', 'failed', 'cancelled'] as RunStatus[])(
    'asks once the run is %s', async (status) => {
      show(status)
      // Failed and cancelled included deliberately: the findings a partial run
      // did write are still open, and the system still has a plan.
      await waitFor(() => expect(remediationPlan).toHaveBeenCalledWith(1))
    })

  it('asks for the plan by SYSTEM, not by run', async () => {
    show()
    await waitFor(() => expect(remediationPlan).toHaveBeenCalled())
    // run id is 7, system id is 1. A plan keyed on the run would be the changes
    // for one upload rather than the changes outstanding on the system.
    expect(remediationPlan).toHaveBeenCalledWith(1)
    expect(remediationPlan).not.toHaveBeenCalledWith(7)
  })

  it('asks for nothing when the run named no system', async () => {
    run.mockResolvedValue({ ...RUN, system_id: null })
    runDiff.mockResolvedValue(null)
    remediationPlan.mockResolvedValue(PLAN)
    render(<MemoryRouter><RunDetail /></MemoryRouter>)
    // Same anchor argument as the in-flight cases: wait for the fetched row to
    // be on screen, so the absence of the request is the guard's doing.
    await screen.findByText(/Landscape 3/)
    await Promise.resolve()
    expect(remediationPlan).not.toHaveBeenCalled()
  })
})

/** A role_authorization block: PFCG coordinates, which are steps and not SQL. */
const STEP_PLAN: RemediationPlan = {
  ...PLAN,
  blocks: [{
    kind: 'role_authorization',
    where: 'PFCG — PRD',
    executable: false,
    apply: ['PFCG > Z_BASIS_SUPER > Authorizations > S_RFCACL — restrict or remove: RFC_USER=*'],
    rollback: ['PFCG > Z_BASIS_SUPER > Authorizations > S_RFCACL — restore: RFC_USER=*'],
    closes: ['AUTH-002'],
    caveats: ['PFCG does not apply a change until the profile is regenerated.'],
  }],
  changes: 1,
}

describe('a block that is steps rather than statements', () => {
  it('does not render PFCG coordinates in a script box', async () => {
    show('complete', STEP_PLAN)
    await waitFor(() => expect(screen.getByText(/What to change on PRD/)).toBeTruthy())
    // <pre> is where this screen puts things to run. PFCG is a dialog
    // transaction, and a monospace block reads as a script somebody can paste.
    expect(document.querySelectorAll('pre').length).toBe(0)
    expect(document.querySelectorAll('ol').length).toBeGreaterThan(0)
  })

  it('labels them as steps', async () => {
    show('complete', STEP_PLAN)
    await waitFor(() => expect(screen.getByText('Steps to follow')).toBeTruthy())
    expect(screen.getByText('To undo')).toBeTruthy()
    expect(screen.queryByText('Roll back, in this order')).toBeNull()
  })

  it('still shows the coordinates and the caveat', async () => {
    show('complete', STEP_PLAN)
    await waitFor(() => expect(screen.getByText(/What to change on PRD/)).toBeTruthy())
    expect(body()).toContain('Z_BASIS_SUPER')
    expect(body()).toContain('RFC_USER=*')
    expect(body()).toContain('regenerated')
  })

  it('keeps rendering a runnable block as a script', async () => {
    show()
    await waitFor(() => expect(screen.getByText(/What to change on PRD/)).toBeTruthy())
    expect(document.querySelectorAll('pre').length).toBeGreaterThan(0)
    expect(screen.getByText('Roll back, in this order')).toBeTruthy()
  })
})
