/**
 * Threat Hunt screen.
 *
 * THE RULE THIS SCREEN KEEPS. It never claims a hunt you cannot run (the banner
 * says a match is a lead, not a verdict; `huntable` reflects whether the log was
 * supplied), and an exploited note with no authored pack is shown without invented
 * indicators.
 */
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const threatHunt = vi.fn()

vi.mock('../api/client', () => ({
  threatHunt: (...a: unknown[]) => threatHunt(...a),
  ApiError: class ApiError extends Error {
    status: number
    constructor(status: number, message: string) { super(message); this.status = status }
  },
}))
vi.mock('../lib/title', () => ({ useTitle: () => {} }))

import { ThreatHunt } from './ThreatHunt'

const LOGS = [
  { id: 'security_audit_log', label: 'Security Audit Log', module: 'log_review', supplied: false },
  { id: 'logserv_events', label: 'SAP LogServ (ICM / gateway)', module: 'logserv_review', supplied: true },
]

function view(over: Record<string, unknown> = {}) {
  return {
    threats: [{
      note: '3594142', cve: 'CVE-2025-31324', name: 'VC Metadata Uploader',
      summary: 'Unauthenticated upload to AS Java.', campaign: 'Mass-exploited in 2025.', cvss: 10.0,
      indicators: [{ log: 'logserv_events', log_label: 'SAP LogServ (ICM / gateway)',
                     signature: 'POST /developmentserver/metadatauploader', meaning: 'the exploitation primitive',
                     log_supplied: true }],
      confirm: ['Inspect irj/root for webshells'], references: ['CISA KEV — CVE-2025-31324', 'SAP Note 3594142'],
      log_sources: ['logserv_events'], huntable: true,
    }],
    without_pack: [{ note: '9999999', cvss: 8.1 }],
    logs: LOGS,
    totals: { exploited_missing: 2, with_pack: 1, without_pack: 1, huntable_now: 1, measured: null },
    ...over,
  }
}

function empty() {
  return {
    threats: [], without_pack: [], logs: LOGS,
    totals: { exploited_missing: 0, with_pack: 0, without_pack: 0, huntable_now: 0, measured: null },
  }
}

function draw() {
  return render(<MemoryRouter><ThreatHunt /></MemoryRouter>)
}

beforeEach(() => vi.clearAllMocks())

describe('Threat Hunt', () => {
  it('shows a hunt pack with its CVE, indicator and huntable status', async () => {
    threatHunt.mockResolvedValue(view())
    draw()
    // exact string: the CVE also appears inside the references line, so a substring
    // regex would match two nodes.
    expect(await screen.findByText('CVE-2025-31324')).toBeInTheDocument()
    expect(screen.getByText(/metadatauploader/)).toBeInTheDocument()
    expect(screen.getByText('huntable now')).toBeInTheDocument()
  })

  it('states that a match is a lead, not a verdict', async () => {
    threatHunt.mockResolvedValue(view())
    draw()
    expect(await screen.findByText(/A match is a lead, not a verdict/)).toBeInTheDocument()
  })

  it('lists an exploited note with no pack, without inventing indicators', async () => {
    threatHunt.mockResolvedValue(view())
    draw()
    expect(await screen.findByText(/9999999/)).toBeInTheDocument()
    expect(screen.getByText(/no hunt pack\s+authored yet/)).toBeInTheDocument()
  })

  it('shows the honest empty state when nothing exploited is unapplied', async () => {
    threatHunt.mockResolvedValue(empty())
    draw()
    expect(await screen.findByText(/No actively-exploited SAP note is unapplied/)).toBeInTheDocument()
  })

  it('reports a load failure instead of a blank screen', async () => {
    threatHunt.mockRejectedValue(new Error('boom'))
    draw()
    expect(await screen.findByText(/Could not load the threat hunt/)).toBeInTheDocument()
  })
})
