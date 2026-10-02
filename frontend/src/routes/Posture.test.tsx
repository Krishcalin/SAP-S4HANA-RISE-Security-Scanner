/**
 * Vulnerabilities & Mis-Configuration — the two posture lenses.
 *
 * One component, two routes. Each must render its class's findings grouped by
 * subject, and a fully-empty class must say "nothing found" rather than draw a
 * reassuring blank (an empty group can mean the feeding data was never supplied).
 */
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const vulnerabilities = vi.fn()
const misconfiguration = vi.fn()

vi.mock('../api/client', () => ({
  vulnerabilities: (...a: unknown[]) => vulnerabilities(...a),
  misconfiguration: (...a: unknown[]) => misconfiguration(...a),
  ApiError: class ApiError extends Error {
    status: number
    constructor(status: number, message: string) { super(message); this.status = status }
  },
}))
vi.mock('../lib/title', () => ({ useTitle: () => {} }))

import { Misconfiguration, Vulnerabilities } from './Posture'

const ZERO = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }

function row(over: Record<string, unknown> = {}) {
  return {
    id: 1, check_id: 'HOTNEWS-001', severity: 'CRITICAL', priority_tier: 'P1',
    title: 'Missing HotNews note 3627998', category: 'SAP Security Notes (HotNews)',
    sid: 'PRD', state: 'open', ...over,
  }
}
function group(id: string, label: string, over: Record<string, unknown> = {}) {
  return { id, label, blurb: `${label} blurb`, counts: { ...ZERO }, total: 0,
           findings: [], ...over }
}
function vulnView(over: Record<string, unknown> = {}) {
  return {
    kind: 'vulnerability',
    groups: [
      group('patches', 'Missing SAP Security Notes',
        { total: 1, counts: { ...ZERO, CRITICAL: 1 }, findings: [row()] }),
      group('native_code', 'Custom code — our scanner'),
      group('atc_code', 'Custom code — SAP ATC / CVA'),
      group('other_code', 'Other code weaknesses'),
    ],
    measured: null,
    totals: { findings: 1, counts: { ...ZERO, CRITICAL: 1 } },
    ...over,
  }
}
function misconfigView() {
  return {
    kind: 'misconfiguration',
    groups: [
      group('parameters', 'Parameters & policy', {
        total: 1, counts: { ...ZERO, HIGH: 1 },
        findings: [row({ id: 2, check_id: 'PARAM-0001', severity: 'HIGH',
                         priority_tier: 'P2', title: 'login/password_expiration too high',
                         category: 'Security Baseline Parameters' })],
      }),
      group('network', 'Network, RFC & interfaces'),
    ],
    measured: null,
    totals: { findings: 1, counts: { ...ZERO, HIGH: 1 } },
  }
}
function emptyVuln() {
  return {
    kind: 'vulnerability',
    groups: ['patches', 'native_code', 'atc_code', 'other_code'].map((id) => group(id, id)),
    measured: null,
    totals: { findings: 0, counts: { ...ZERO } },
  }
}

beforeEach(() => { vi.clearAllMocks() })

describe('Vulnerabilities & Mis-Configuration', () => {
  it('lists a vulnerability under its source group', async () => {
    vulnerabilities.mockResolvedValue(vulnView())
    render(<MemoryRouter><Vulnerabilities /></MemoryRouter>)
    expect(await screen.findByText(/Missing HotNews note 3627998/)).toBeInTheDocument()
    expect(screen.getByText('Missing SAP Security Notes')).toBeInTheDocument()
    expect(screen.getByText('P1')).toBeInTheDocument()
  })

  it('lists a misconfiguration under its subject group', async () => {
    misconfiguration.mockResolvedValue(misconfigView())
    render(<MemoryRouter><Misconfiguration /></MemoryRouter>)
    expect(await screen.findByText(/login\/password_expiration too high/)).toBeInTheDocument()
    expect(screen.getByText('Parameters & policy')).toBeInTheDocument()
  })

  it('shows a "nothing found" banner on an empty class', async () => {
    vulnerabilities.mockResolvedValue(emptyVuln())
    render(<MemoryRouter><Vulnerabilities /></MemoryRouter>)
    expect(await screen.findByText(/No vulnerabilities found/)).toBeInTheDocument()
  })

  it('reports a load failure instead of a blank screen', async () => {
    misconfiguration.mockRejectedValue(new Error('boom'))
    render(<MemoryRouter><Misconfiguration /></MemoryRouter>)
    expect(await screen.findByText(/Could not load the misconfiguration findings/))
      .toBeInTheDocument()
  })
})
