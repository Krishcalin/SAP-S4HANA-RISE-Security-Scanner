import { render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { EvidenceGaps } from './EvidenceGaps'
import type { EvidenceGap, EvidenceGapsView } from '../api/types'

/**
 * The screen that ranks what to send next.
 *
 * Everything that can go wrong here is a WORDING failure rather than a rendering
 * one, which is why these tests read the sentences and not just the numbers.
 *
 *   IT MUST NOT PROMISE AN OUTCOME. "Would fix 35 findings" is the sentence this
 *   page must never say. The scanner has no connection to SAP and does not know
 *   what those checks will conclude — that is the entire reason the export is
 *   being requested. `it_never_promises_what_the_answers_will_be` pins the verb.
 *
 *   THE HEADLINE IS NOT THE COLUMN'S SUM. A finding waiting on two exports is
 *   one undecided finding in two rows. A reader who adds the column up and gets
 *   a larger number than the headline will trust neither, so the page says which
 *   is which in words.
 *
 *   A GAP THE CUSTOMER CANNOT CLOSE MUST SAY SO. Ranking an OS-level export
 *   first for a RISE customer hands them an item they can only fail.
 *
 *   AN EMPTY LIST IS GOOD NEWS HERE, uniquely in this product. Everywhere else
 *   an empty list is the ambiguity to be resolved; on this page it means every
 *   open finding reached its verdict on complete input, and it must not render
 *   as the same shrug.
 */

vi.mock('../api/client', () => ({
  evidenceGaps: vi.fn(),
  ApiError: class ApiError extends Error {
    status: number
    constructor(status: number, message: string) {
      super(message)
      this.status = status
    }
  },
}))

vi.mock('../lib/title', () => ({ useTitle: () => {} }))

import { evidenceGaps as fetchEvidenceGaps } from '../api/client'

function gap(over: Partial<EvidenceGap> = {}): EvidenceGap {
  return {
    source: 'auth_objects',
    findings_undecided: 35,
    checks: 35,
    systems: 2,
    files_accepted: ['auth_objects.csv'],
    feeds: ['security_params'],
    known_to_loader: true,
    obtainable_in_rise: true,
    ...over,
  }
}

function view(over: Partial<EvidenceGapsView> = {}): EvidenceGapsView {
  return {
    gaps: [gap()],
    findings_undecided: 35,
    unknown_sources: [],
    ...over,
  }
}

const mocked = vi.mocked(fetchEvidenceGaps)

/** The ranked table, scoped. The source name and the undecided count each appear
 *  twice on a rendered page — once in the summary tile, once in the row — so an
 *  unscoped getByText matches two elements and throws. Scoping also makes the
 *  assertions mean what they say: "the row shows this", not "the page mentions
 *  it somewhere". */
const table = () => within(screen.getByRole('table'))

describe('EvidenceGaps', () => {
  beforeEach(() => { vi.clearAllMocks() })

  it('ranks the sources in the order the API returned them', async () => {
    // THE HEAVY SOURCE IS THE LATER ONE ALPHABETICALLY, deliberately. With the
    // counts the other way round a page that re-sorted by name would produce the
    // identical list, and this test would pass while defending nothing — the
    // mutation that re-sorts survived until these two were swapped.
    mocked.mockResolvedValue(view({
      gaps: [
        gap({ source: 'user_groups', findings_undecided: 35 }),
        gap({ source: 'auth_objects', findings_undecided: 3 }),
      ],
      findings_undecided: 38,
    }))
    render(<EvidenceGaps />)
    await waitFor(() => expect(screen.getByRole('table')).toBeInTheDocument())
    const cells = screen.getAllByText(/^(auth_objects|user_groups)$/)
    // Three matches: the "send this first" tile, then the two rows. The tile and
    // the first row must name the same source, or the page contradicts itself.
    expect(cells.map((c) => c.textContent)).toEqual(
      ['user_groups', 'user_groups', 'auth_objects'])
  })

  it('names the heaviest source as the one to send first', async () => {
    mocked.mockResolvedValue(view({
      gaps: [gap({ source: 'auth_objects', findings_undecided: 35, checks: 35 })],
    }))
    render(<EvidenceGaps />)
    await waitFor(() => expect(screen.getByText('Send this first')).toBeInTheDocument())
    expect(screen.getByText(/35 findings across 35 checks reach a verdict/))
      .toBeInTheDocument()
  })

  it('never promises what the answers will be', async () => {
    mocked.mockResolvedValue(view())
    render(<EvidenceGaps />)
    await waitFor(() => expect(screen.getByRole('table')).toBeInTheDocument())
    const page = document.body.textContent ?? ''
    // "resolve" is absent too: a finding here may well stay open once decided.
    expect(page).not.toMatch(/would fix|will fix|would resolve|fixes \d/i)
    expect(page).toMatch(/reach a verdict/i)
    expect(page).toMatch(/it does not say what they will answer/i)
  })

  it('says the headline is not the sum of the column', async () => {
    mocked.mockResolvedValue(view({
      gaps: [gap({ source: 'auth_objects', findings_undecided: 2 }),
             gap({ source: 'user_groups', findings_undecided: 2 })],
      // One finding waiting on both: three undecided findings, four row-mentions.
      findings_undecided: 3,
    }))
    render(<EvidenceGaps />)
    await waitFor(() => expect(screen.getByRole('table')).toBeInTheDocument())
    // The tile, not a row: the rows here read 2 and 2, and the headline is 3.
    expect(screen.getByText('Findings undecided').parentElement)
      .toHaveTextContent('3')
    expect(screen.getByText(/counted once here and appears in both rows/))
      .toBeInTheDocument()
  })

  it('marks a source SAP operates rather than telling the customer to fetch it',
     async () => {
       mocked.mockResolvedValue(view({
         gaps: [gap({ source: 'ext_os_commands_sap', obtainable_in_rise: false })],
       }))
       render(<EvidenceGaps />)
       await waitFor(() => expect(screen.getByRole('table')).toBeInTheDocument())
       expect(table().getByText('ext_os_commands_sap')).toBeInTheDocument()
       expect(table().getByText(/SAP operates this layer under RISE/))
         .toBeInTheDocument()
     })

  it('leaves an obtainable source unmarked', async () => {
    // The negative control: without it the assertion above passes on a page that
    // prints that sentence on every row.
    mocked.mockResolvedValue(view())
    render(<EvidenceGaps />)
    await waitFor(() => expect(screen.getByRole('table')).toBeInTheDocument())
    expect(screen.queryByText(/SAP operates this layer under RISE/)).toBeNull()
  })

  it('calls out a source no export can satisfy as our defect', async () => {
    mocked.mockResolvedValue(view({
      gaps: [gap({ source: 'auth_objekts', known_to_loader: false,
                   files_accepted: [] })],
      unknown_sources: ['auth_objekts'],
    }))
    render(<EvidenceGaps />)
    await waitFor(() =>
      expect(screen.getByText(/is not one the loader accepts/)).toBeInTheDocument())
    expect(screen.getByText(/defect in the check, not something to collect/))
      .toBeInTheDocument()
  })

  it('shows no defect banner when every source is one we accept', async () => {
    mocked.mockResolvedValue(view())
    render(<EvidenceGaps />)
    await waitFor(() => expect(screen.getByRole('table')).toBeInTheDocument())
    expect(screen.queryByText(/is not one the loader accepts/)).toBeNull()
  })

  it('offers the filenames the loader will accept', async () => {
    mocked.mockResolvedValue(view({
      gaps: [gap({ files_accepted: ['auth_objects.csv', 'tobj.csv'] })],
    }))
    render(<EvidenceGaps />)
    await waitFor(() =>
      expect(screen.getByText('auth_objects.csv · tobj.csv')).toBeInTheDocument())
  })

  it('reads an empty list as the good news it is', async () => {
    mocked.mockResolvedValue(view({ gaps: [], findings_undecided: 0 }))
    render(<EvidenceGaps />)
    await waitFor(() =>
      expect(screen.getByText('Nothing outstanding')).toBeInTheDocument())
    expect(screen.getByText(/reached its verdict on complete input/))
      .toBeInTheDocument()
    // Not the ambiguous empty state this product spends its time telling apart.
    expect(screen.queryByText(/Ranked by findings waiting/)).toBeNull()
  })

  it('explains a refusal rather than rendering an empty page', async () => {
    const { ApiError } = await import('../api/client')
    mocked.mockRejectedValue(new (ApiError as new (s: number, m: string) => Error)(
      403, 'forbidden'))
    render(<EvidenceGaps />)
    await waitFor(() =>
      expect(screen.getByText(/not permitted to see the estate/)).toBeInTheDocument())
  })
})
