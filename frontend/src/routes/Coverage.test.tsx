import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { Coverage } from './Coverage'
import type { Coverage as CoverageView } from '../api/types'

/**
 * The honesty screen, and the two ways its denominator can lie.
 *
 * INFLATING IT. Ten of SAP's 38 published requirements are NetWeaver AS Java, a
 * stack this product does not read at all. Measuring coverage against 38 reports
 * as a gap something no amount of work here would close, and a reader has no way
 * to tell that from the number alone.
 *
 * FLATTERING IT. The correction has the opposite failure mode, and it is the
 * worse one: quietly dropping a technology from the denominator raises the
 * percentage without changing a single check. That is why the excluded
 * requirements are still listed, with the reason, and why a covered requirement
 * can never be moved out of scope — tested here and in
 * `tests/test_baseline_scope_gaps.py`, because the rule has to hold on both
 * sides of the API.
 */

vi.mock('../api/client', () => ({
  coverage: vi.fn(),
  ApiError: class ApiError extends Error {
    status: number
    constructor(status: number, message: string) {
      super(message)
      this.status = status
    }
  },
}))

vi.mock('../lib/title', () => ({ useTitle: () => {} }))

import { coverage as fetchCoverage } from '../api/client'

function view(over: Partial<CoverageView> = {}): CoverageView {
  return {
    baseline_version: 'v2.4',
    requirements_published: 38,
    requirements_in_scope: 28,
    requirements_covered: 28,
    covered: [{
      requirement: 'NETCF-H', tier: 'CRITICAL', technology: 'HANA',
      title: 'HANA internal communication (listeninterface)',
      our_checks: ['HANADB-PARAM-006'],
    }],
    not_covered: [],
    // One representative excluded row rather than all ten: the assertions below
    // read the count off this list, not off `requirements_published`.
    out_of_scope: [{
      requirement: 'PWDPOL-J', tier: 'CRITICAL', technology: 'Java',
      title: 'Minimum Password Length',
      reason: 'SAP NetWeaver AS Java is a separate stack from the ABAP server '
              + 'S/4HANA runs on.',
    }],
    beyond_baseline: ['GRC-EAM-001', 'FIN-PP-001'],
    note: '',
    meta: {},
    our_checks: 432,
    observed_checks: 190,
    ...over,
  }
}

function renderPage() {
  return render(<MemoryRouter><Coverage /></MemoryRouter>)
}

describe('Coverage — the denominator', () => {
  beforeEach(() => vi.clearAllMocks())

  it('measures against what is in scope, not against everything published', async () => {
    vi.mocked(fetchCoverage).mockResolvedValue(view())
    renderPage()
    // 28 of 28, not 28 of 38. The published total still has to be visible, so
    // the narrower denominator is something the reader can see rather than
    // something they have to take on trust.
    await waitFor(() =>
      expect(screen.getByText(/of 38 out of scope/)).toBeTruthy())
    // Read the meter's own accessible value rather than hunting for a 28 in the
    // text: the figure and its ceiling are separate elements, and this is the
    // pair a screen reader is given.
    const meter = screen.getByRole('meter')
    expect(meter.getAttribute('aria-valuenow')).toBe('28')
    expect(meter.getAttribute('aria-valuemax')).toBe('28')
  })

  it('names every excluded requirement, and the reason', async () => {
    vi.mocked(fetchCoverage).mockResolvedValue(view())
    renderPage()
    await waitFor(() =>
      expect(screen.getByText(/Requirements out of scope/)).toBeTruthy())
    expect(screen.getByText('PWDPOL-J')).toBeTruthy()
    expect(screen.getByText(/separate stack from the ABAP server/)).toBeTruthy()
  })

  it('does not claim depth when it has only closed the last gap', async () => {
    vi.mocked(fetchCoverage).mockResolvedValue(view())
    renderPage()
    // Zero gaps is a narrow claim and the page has to keep it narrow: SAP's 38
    // requirements carry 351 check items, and answering each requirement is not
    // reproducing each item.
    await waitFor(() =>
      expect(screen.getByText(/351 check items/)).toBeTruthy())
  })

  it('still reports an in-scope gap as a gap', async () => {
    vi.mocked(fetchCoverage).mockResolvedValue(view({
      requirements_covered: 27,
      not_covered: [{
        requirement: 'TRACES-H', tier: 'CRITICAL', technology: 'HANA',
        title: 'SQL trace level: ALL_WITH_RESULTS',
      }],
    }))
    renderPage()
    await waitFor(() => expect(screen.getByText('TRACES-H')).toBeTruthy())
    // The banner splits "inside" into its own <strong>, so match on the node's
    // full text rather than on a single text node.
    expect(screen.getByText(
      (_, el) => /gaps\s+inside\s+the stack/i.test(el?.textContent ?? ''),
      { selector: '.banner-warn' })).toBeTruthy()
    // And the out-of-scope table is still there — one does not replace the other.
    expect(screen.getByText('PWDPOL-J')).toBeTruthy()
  })

  it('omits the out-of-scope section entirely when nothing is excluded', async () => {
    vi.mocked(fetchCoverage).mockResolvedValue(view({ out_of_scope: [] }))
    renderPage()
    await waitFor(() => expect(screen.getByText('NETCF-H')).toBeTruthy())
    expect(screen.queryByText(/Requirements out of scope/)).toBeNull()
  })
})
