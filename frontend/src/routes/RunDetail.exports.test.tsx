/**
 * "Which export to supply next" on the run page.
 *
 * THE TABLE ABOVE IT ALREADY LISTS THE MISSING SOURCES and stops there, which
 * leaves the reader with filenames and no way to tell which one is worth going
 * back to Basis for. On a five-source gap `export_value.rank` says `users`
 * alone would let 21 more checks run and `saprouttab` one — that ordering is the
 * whole point, and an alphabetical render would put the least useful export at
 * the top while looking exactly as authoritative.
 *
 * TWO NUMBERS THAT MUST NOT BE ADDED. `unlocks_now` is what supplying this one
 * file achieves; `also_needed_by` still waits on another source that is also
 * missing. Summed into a single "would unlock N", the row promises for one
 * upload what needs two.
 *
 * AND THE RISE SPLIT. `unobtainable` sources need OS access the customer does
 * not have under the contract. They are the reason a gap exists and never a next
 * step, so they must render apart from the ranking — a row that reads "fetch
 * gw_reginfo" sends somebody to ask SAP for a file the contract does not let
 * them have.
 */
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const run = vi.fn()
const runDiff = vi.fn()
const runExportValue = vi.fn()

vi.mock('../api/client', () => ({
  run: (...a: unknown[]) => run(...a),
  runDiff: (...a: unknown[]) => runDiff(...a),
  runExportValue: (...a: unknown[]) => runExportValue(...a),
  remediationPlan: () => Promise.reject(new Error('not this test')),
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
import type { ExportValue, RunStatus, ScanRun } from '../api/types'

const RUN = {
  id: 7,
  landscape_id: 3,
  system_id: 1,
  status: 'complete' as RunStatus,
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

/** `export_value.rank` on a manifest missing five real logical sources, run
 *  under RISE. Every number below is the module's own output, not invented:
 *  users 21, security_params 13, user_roles 8, and the two OS-level sources
 *  moved out of the ranking. */
const VALUE: ExportValue = {
  ranked: [
    { source: 'users', unlocks_now: 21, also_needed_by: 1,
      checks: [], modules: ['iam_advanced', 'user_auth_audit'], obtainable: true },
    { source: 'security_params', unlocks_now: 13, also_needed_by: 1,
      checks: [], modules: ['baseline_params', 'crypto_posture'], obtainable: true },
    { source: 'user_roles', unlocks_now: 8, also_needed_by: 0,
      checks: [], modules: ['role_governance'], obtainable: true },
  ],
  unobtainable: [
    { source: 'gw_reginfo', unlocks_now: 3, also_needed_by: 0,
      checks: [], modules: ['ucon_exposure'], obtainable: false },
    { source: 'saprouttab', unlocks_now: 1, also_needed_by: 0,
      checks: [], modules: ['system_trust'], obtainable: false },
  ],
  missing: 5,
  checks_blocked: 47,
}

function show(value: ExportValue | null = VALUE, status: RunStatus = 'complete') {
  run.mockResolvedValue({ ...RUN, status })
  runDiff.mockResolvedValue(null)
  runExportValue.mockImplementation(
    () => value ? Promise.resolve(value) : Promise.reject(new Error('404')))
  return render(<MemoryRouter><RunDetail /></MemoryRouter>)
}

function body(): string { return document.body.textContent ?? '' }

const PHASE_TEXT: Partial<Record<RunStatus, string>> = {
  pending: 'Queued. The scan starts when a worker picks the bundle up.',
  scanning: 'Running the audit modules.',
}

beforeEach(() => { vi.clearAllMocks() })

describe('which export to supply next', () => {
  it('names the sources in the order the server ranked them', async () => {
    show()
    await waitFor(() => expect(screen.getByText(/Which export to supply next/)).toBeTruthy())
    const text = body()
    // Not alphabetical: `security_params` sorts before `user_roles` and
    // `users`, and would lead an alphabetised table.
    expect(text.indexOf('users')).toBeLessThan(text.indexOf('security_params'))
    expect(text.indexOf('security_params')).toBeLessThan(text.indexOf('user_roles'))
  })

  it('shows what one source alone would unlock', async () => {
    show()
    await waitFor(() => expect(screen.getByText('21')).toBeTruthy())
    expect(screen.getByText('13')).toBeTruthy()
    expect(screen.getByText('8')).toBeTruthy()
  })

  it('keeps "needs another too" in its own column', async () => {
    show()
    await waitFor(() => expect(screen.getByText(/Needs another too/)).toBeTruthy())
    // 21 and 1 must both be on the page and never as 22: supplying `users`
    // alone does not make the 22nd check run.
    expect(body()).not.toMatch(/\b22\b/)
  })

  it('states the size of the gap the ranking is drawn from', async () => {
    show()
    await waitFor(() => expect(screen.getByText(/Which export to supply next/)).toBeTruthy())
    expect(body()).toMatch(/5 source\(s\) were missing/)
    expect(body()).toMatch(/47 check\(s\)/)
  })

  it('names the modules each source feeds', async () => {
    show()
    await waitFor(() => expect(body()).toContain('iam_advanced'))
    expect(body()).toContain('crypto_posture')
  })

  // ── the RISE split ────────────────────────────────────────────────────────

  it('keeps unobtainable sources out of the ranking table', async () => {
    show()
    await waitFor(() => expect(screen.getByText(/Which export to supply next/)).toBeTruthy())
    const rows = screen.getAllByRole('row')
    const inTable = rows.map((r) => r.textContent ?? '').join(' ')
    expect(inTable).toContain('users')
    expect(inTable).not.toContain('gw_reginfo')
    expect(inTable).not.toContain('saprouttab')
  })

  it('still reports them, as the reason those checks did not run', async () => {
    show()
    await waitFor(() => expect(screen.getByText(/Not obtainable under RISE/)).toBeTruthy())
    const text = body()
    expect(text).toContain('gw_reginfo')
    expect(text).toContain('saprouttab')
    expect(text).toMatch(/not something to go and ask for/)
  })

  it('says so plainly when nothing missing can be supplied at all', async () => {
    show({ ...VALUE, ranked: [] })
    await waitFor(() =>
      expect(screen.getByText(/Nothing missing here can be supplied/)).toBeTruthy())
  })

  // ── when there is nothing to say ──────────────────────────────────────────

  it('renders no section when the upload was complete', async () => {
    show({ ranked: [], unobtainable: [], missing: 0, checks_blocked: 0 })
    await waitFor(() => expect(runExportValue).toHaveBeenCalled())
    expect(screen.queryByText(/Which export to supply next/)).toBeNull()
  })

  it('renders no section when the endpoint could not answer', async () => {
    show(null)
    await waitFor(() => expect(runExportValue).toHaveBeenCalled())
    expect(screen.queryByText(/Which export to supply next/)).toBeNull()
  })

  // ── timing ────────────────────────────────────────────────────────────────

  it.each(['pending', 'scanning'] as RunStatus[])(
    'does not ask while the run is %s', async (status) => {
      show(VALUE, status)
      // `coverage` is written at the END of the pipeline, so mid-scan the column
      // is still `{}` and rank({}) answers "nothing is missing" — the most
      // reassuring possible reading of a run that has not looked yet. Waiting on
      // rendered phase text rather than on the fetch call, so the absence proves
      // the guard and not the clock.
      await screen.findByText(PHASE_TEXT[status]!)
      await Promise.resolve()
      expect(runExportValue).not.toHaveBeenCalled()
    })

  it('asks once the run is terminal', async () => {
    show()
    await waitFor(() => expect(runExportValue).toHaveBeenCalledWith(7))
  })
})
