/**
 * Perceived Threats — the SAP LogServ observation view.
 *
 * THE RULE THIS SCREEN KEEPS. An empty log class is not a clean one: if a class
 * is not being forwarded, its group is empty for want of data. So the coverage &
 * health section must render, and a fully-empty estate must say "nothing ingested
 * yet" rather than draw a reassuring blank.
 */
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const perceivedThreats = vi.fn()

vi.mock('../api/client', () => ({
  perceivedThreats: (...a: unknown[]) => perceivedThreats(...a),
  ApiError: class ApiError extends Error {
    status: number
    constructor(status: number, message: string) { super(message); this.status = status }
  },
}))
vi.mock('../lib/title', () => ({ useTitle: () => {} }))

import { PerceivedThreats } from './PerceivedThreats'

const ZERO = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }

function row(over: Record<string, unknown> = {}) {
  return {
    id: 1, check_id: 'LREV-PAT-001', severity: 'HIGH', priority_tier: 'P2',
    title: 'Off-hours privileged logon', category: 'Security Audit Log Review',
    sid: 'PRD', state: 'open',
    attack: { technique: 'T1078', technique_name: 'Valid Accounts',
              tactic: 'Initial Access', confidence: 'high' },
    ...over,
  }
}
function group(id: string, label: string, over: Record<string, unknown> = {}) {
  return { id, label, blurb: `${label} blurb`, counts: { ...ZERO }, total: 0,
           findings: [], ...over }
}
function fullView(over: Record<string, unknown> = {}) {
  return {
    groups: [
      group('audit_behaviour', 'Audit-log behaviour',
        { total: 1, counts: { ...ZERO, HIGH: 1 }, findings: [row()] }),
      group('violations', 'Access violations'),
      group('gateway', 'Gateway / RFC'),
      group('hana', 'HANA database'),
      group('icm_web', 'ICM / web'),
      group('network', 'Network'),
    ],
    health: [
      group('ingestion', 'LogServ ingestion health', {
        total: 1, counts: { ...ZERO, MEDIUM: 1 },
        findings: [row({ id: 2, check_id: 'LSRV-COV-001', severity: 'MEDIUM',
                         priority_tier: 'P3', title: 'Gateway log not forwarded',
                         attack: null })],
      }),
      group('audit_coverage', 'Audit-log coverage'),
    ],
    measured: null,
    totals: { threats: 1, health: 1, counts: { ...ZERO, HIGH: 1 } },
    ...over,
  }
}
function emptyView() {
  return {
    groups: ['audit_behaviour', 'violations', 'gateway', 'hana', 'icm_web', 'network']
      .map((id) => group(id, id)),
    health: ['ingestion', 'audit_coverage'].map((id) => group(id, id)),
    measured: null,
    totals: { threats: 0, health: 0, counts: { ...ZERO } },
  }
}
function draw() {
  return render(<MemoryRouter><PerceivedThreats /></MemoryRouter>)
}

beforeEach(() => { vi.clearAllMocks() })

describe('Perceived Threats', () => {
  it('lists an observed threat under its log class with the tier that ranked it', async () => {
    perceivedThreats.mockResolvedValue(fullView())
    draw()
    expect(await screen.findByText(/Off-hours privileged logon/)).toBeInTheDocument()
    expect(screen.getByText('Audit-log behaviour')).toBeInTheDocument()
    expect(screen.getByText('P2')).toBeInTheDocument()
    // the MITRE ATT&CK technique badge for this observed behaviour
    expect(screen.getByText('T1078')).toBeInTheDocument()
  })

  it('renders the LogServ coverage & health section with its own findings', async () => {
    perceivedThreats.mockResolvedValue(fullView())
    draw()
    expect(await screen.findByRole('heading', { name: /LogServ coverage/ }))
      .toBeInTheDocument()
    expect(screen.getByText(/Gateway log not forwarded/)).toBeInTheDocument()
  })

  it('shows a "nothing ingested" banner when the estate has no log data', async () => {
    perceivedThreats.mockResolvedValue(emptyView())
    draw()
    expect(await screen.findByText(/No SAP LogServ logs have been ingested/))
      .toBeInTheDocument()
  })

  it('reports a load failure instead of a blank screen', async () => {
    perceivedThreats.mockRejectedValue(new Error('boom'))
    draw()
    expect(await screen.findByText(/Could not load the perceived threats/))
      .toBeInTheDocument()
  })
})
