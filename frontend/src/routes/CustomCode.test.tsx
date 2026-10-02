/**
 * Custom Code — the ABAP/custom-code posture view.
 *
 * THE RULE THIS SCREEN KEEPS. An empty weakness is not a clean one: if no ABAP
 * source was scanned, every group is empty for want of input. So the scan
 * coverage & trust section must render, and a fully-empty estate must say "nothing
 * scanned yet" rather than draw a reassuring blank. The screen must also surface
 * the signal the generic queue hides — the CWE family, the worst objects, and the
 * SAP-ATC-vs-native provenance.
 */
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const customCode = vi.fn()

vi.mock('../api/client', () => ({
  customCode: (...a: unknown[]) => customCode(...a),
  ApiError: class ApiError extends Error {
    status: number
    constructor(status: number, message: string) { super(message); this.status = status }
  },
}))
vi.mock('../lib/title', () => ({ useTitle: () => {} }))

import { CustomCode } from './CustomCode'

const ZERO = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }

function row(over: Record<string, unknown> = {}) {
  return {
    id: 1, check_id: 'ABAP-SQLI-001', severity: 'CRITICAL', priority_tier: 'P1',
    title: 'Dynamic WHERE built from input — ZCL_VENDOR', object: 'ZCL_VENDOR',
    sid: 'PRD', state: 'open', provenance: 'native', confidence: 'confirmed',
    internet_exposed: true, ...over,
  }
}
function group(id: string, label: string, over: Record<string, unknown> = {}) {
  return { id, label, blurb: `${label} blurb`, cwe: 'CWE-89', counts: { ...ZERO },
           total: 0, native: 0, atc: 0, findings: [], ...over }
}
function fullView(over: Record<string, unknown> = {}) {
  return {
    groups: [
      group('injection_sql', 'SQL & database injection',
        { total: 1, counts: { ...ZERO, CRITICAL: 1 }, native: 1, findings: [row()] }),
      group('injection_os', 'OS command injection', { cwe: 'CWE-78' }),
    ],
    health: [
      group('scan_coverage', 'Scan coverage', {
        cwe: null, total: 1, counts: { ...ZERO, MEDIUM: 1 }, native: 1,
        findings: [row({ id: 2, check_id: 'ABAP-COV-001', severity: 'MEDIUM',
                         priority_tier: 'P3', object: null, confidence: null,
                         internet_exposed: null,
                         title: 'Part of the source tree was unreadable' })],
      }),
      group('atc_evidence', 'SAP ATC / CVA evidence', { cwe: null }),
    ],
    objects: [
      { name: 'ZCL_VENDOR', total: 2, counts: { ...ZERO, CRITICAL: 1, HIGH: 1 },
        native: 2, atc: 0, worst: 'CRITICAL' },
    ],
    measured: null,
    totals: {
      findings: 1, trust: 1, objects: 1, counts: { ...ZERO, CRITICAL: 1 },
      provenance: { native: 1, atc: 0 },
      confidence: { confirmed: 1, tentative: 0, unknown: 0 },
      exposure: { exposed: 1, internal: 0, unknown: 0 },
    },
    ...over,
  }
}
function emptyView() {
  return {
    groups: ['injection_sql', 'injection_os'].map((id) => group(id, id)),
    health: ['scan_coverage', 'atc_evidence'].map((id) => group(id, id)),
    objects: [],
    measured: null,
    totals: {
      findings: 0, trust: 0, objects: 0, counts: { ...ZERO },
      provenance: { native: 0, atc: 0 },
      confidence: { confirmed: 0, tentative: 0, unknown: 0 },
      exposure: { exposed: 0, internal: 0, unknown: 0 },
    },
  }
}
function draw() {
  return render(<MemoryRouter><CustomCode /></MemoryRouter>)
}

beforeEach(() => { vi.clearAllMocks() })

describe('Custom Code', () => {
  it('lists a finding under its weakness, with the CWE and the object', async () => {
    customCode.mockResolvedValue(fullView())
    draw()
    expect(await screen.findByText(/Dynamic WHERE built from input/)).toBeInTheDocument()
    expect(screen.getByText('SQL & database injection')).toBeInTheDocument()
    expect(screen.getAllByText('CWE-89').length).toBeGreaterThan(0)
  })

  it('ranks the worst objects', async () => {
    customCode.mockResolvedValue(fullView())
    draw()
    expect(await screen.findByRole('heading', { name: /Worst objects/ }))
      .toBeInTheDocument()
    expect(screen.getAllByText(/ZCL_VENDOR/).length).toBeGreaterThan(0)
  })

  it('renders the scan coverage & trust section with its own findings', async () => {
    customCode.mockResolvedValue(fullView())
    draw()
    expect(await screen.findByRole('heading', { name: 'Scan coverage & trust' }))
      .toBeInTheDocument()
    expect(screen.getByText(/source tree was unreadable/)).toBeInTheDocument()
  })

  it('shows a "nothing scanned" banner when no ABAP source was scanned', async () => {
    customCode.mockResolvedValue(emptyView())
    draw()
    expect(await screen.findByText(/No custom ABAP source has been scanned/))
      .toBeInTheDocument()
  })

  it('reports a load failure instead of a blank screen', async () => {
    customCode.mockRejectedValue(new Error('boom'))
    draw()
    expect(await screen.findByText(/Could not load the custom-code posture/))
      .toBeInTheDocument()
  })
})
