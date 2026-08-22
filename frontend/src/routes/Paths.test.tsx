import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { Paths } from './Paths'
import type { PathsOverview } from '../api/types'

/**
 * The landing screen, and the two things on it that can vanish without breaking.
 *
 * WHY THIS FILE EXISTS. Both features here were reported as unbuilt in
 * docs/BUILD_ROADMAP.md — "the rendering was not found" against the choke-point
 * table, "the BANNER is the missing half" against staleness — and both had in
 * fact shipped. What had NOT shipped was any guard on either, which is how a
 * roadmap comes to disagree with the code in the first place: nothing failed when
 * the claim went stale, and nothing would fail if the rendering went away again.
 *
 * THE STALENESS BANNER IS AN HONESTY FEATURE, not a nicety. A path derived under
 * a superseded ruleset is presented identically to one derived under the current
 * rules unless something says otherwise, which is the same class of defect as a
 * coverage gap rendering as a clean result. A conditional render is exactly the
 * kind of thing a refactor drops silently — it type-checks whether or not it is
 * there.
 */

vi.mock('../api/client', () => ({
  paths: vi.fn(),
  ApiError: class ApiError extends Error {
    status: number
    constructor(status: number, message: string) {
      super(message)
      this.status = status
    }
  },
}))

vi.mock('../lib/title', () => ({ useTitle: () => {} }))

import { paths } from '../api/client'

/** A complete, correctly-shaped overview, built from api/types.ts rather than
 *  guessed, with everything empty except what a test fills in. */
function overview(over: Partial<PathsOverview> = {}): PathsOverview {
  return {
    summary: { open: 0, critical: 0, closed: 0, stale: 0 },
    paths: [],
    chokepoints: [],
    closed: [],
    template_count: 7,
    ...over,
  }
}

function chokepoint(over: Partial<PathsOverview['chokepoints'][0]> = {}) {
  return {
    finding_id: 1,
    paths_cut: 1,
    scenarios: ['Fraudulent payment'],
    check_id: 'AUTH-002',
    severity: 'CRITICAL' as const,
    state: 'open' as const,
    priority_tier: 'P1' as const,
    remediation_owner: 'customer_fixable' as const,
    title: 'Role grants S_RFCACL',
    sid: 'PRD',
    client: '100',
    ...over,
  }
}

async function renderWith(view: PathsOverview) {
  vi.mocked(paths).mockResolvedValue(view)
  render(
    <MemoryRouter>
      <Paths />
    </MemoryRouter>,
  )
  await waitFor(() => expect(paths).toHaveBeenCalled())
}

beforeEach(() => {
  vi.mocked(paths).mockReset()
})

describe('the staleness banner', () => {
  it('says so when paths were derived under an older ruleset', async () => {
    await renderWith(overview({ summary: { open: 4, critical: 1, closed: 0, stale: 3 } }))
    expect(await screen.findByText(/3 path\(s\) were derived under an older ruleset/))
      .toBeInTheDocument()
  })

  it('tells the reader what to do about it', async () => {
    // A warning with no remedy is one the reader learns to skip.
    await renderWith(overview({ summary: { open: 4, critical: 1, closed: 0, stale: 3 } }))
    expect(await screen.findByText(/Re-scan to refresh/)).toBeInTheDocument()
  })

  it('does not appear when every path is current', async () => {
    // A banner on the healthy case is noise, and noise is how the real one gets
    // skipped.
    await renderWith(overview({ summary: { open: 4, critical: 1, closed: 0, stale: 0 } }))
    await screen.findByText('Open paths')
    expect(screen.queryByText(/older ruleset/)).not.toBeInTheDocument()
  })
})

describe('the choke-point table', () => {
  it('states the consequence of closing each one', async () => {
    // "Close this and N paths die" is the landing metric. A table listing
    // findings without their consequence is just the findings queue again.
    await renderWith(overview({ chokepoints: [chokepoint({ paths_cut: 4 })] }))
    expect(await screen.findByText('Role grants S_RFCACL')).toBeInTheDocument()
    expect(screen.getByText('4')).toBeInTheDocument()
    expect(screen.getByText('AUTH-002')).toBeInTheDocument()
  })

  it('links every row to the finding it names', async () => {
    // A list screen that does not link its rows strands the detail screen.
    await renderWith(overview({ chokepoints: [chokepoint({ finding_id: 42 })] }))
    const link = await screen.findByRole('link', { name: 'AUTH-002' })
    expect(link).toHaveAttribute('href', '/findings/42')
  })

  it('carries the ownership so a RISE reader can tell theirs from SAP’s', async () => {
    // In RISE this is the difference between an action and unactionable noise.
    await renderWith(
      overview({ chokepoints: [chokepoint({ remediation_owner: 'ticket_to_sap' })] }),
    )
    expect(await screen.findByText('Raise with SAP')).toBeInTheDocument()
  })

  it('says why the table is empty rather than showing nothing', async () => {
    // An empty table with no explanation reads as a broken screen.
    await renderWith(overview())
    expect(await screen.findByText(/No choke points/)).toBeInTheDocument()
  })

  it('counts the choke points in the summary card', async () => {
    await renderWith(overview({ chokepoints: [chokepoint(), chokepoint({ finding_id: 2 })] }))
    // "Choke points" is deliberately BOTH the summary card and the section
    // heading below it, so the query has to expect two rather than one.
    await waitFor(() => expect(screen.getAllByText('Choke points')).toHaveLength(2))
    expect(screen.getByText('single fixes that sever a path')).toBeInTheDocument()
  })
})
