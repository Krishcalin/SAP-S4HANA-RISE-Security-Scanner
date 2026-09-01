/**
 * Compliance posture, across every framework this product maps.
 *
 * THE RULE THIS SCREEN EXISTS UNDER, and the one a screen is most likely to
 * break: a control carrying findings has open gaps, and the ABSENCE of findings
 * against a control is not an assertion of compliance with it. This product
 * reads configuration exports, not the control environment.
 * `modules/compliance_mapping.py` forbids a percentage in as many words — and a
 * page is exactly where one gets invented, as a progress bar, a donut, or a
 * "9 of 12 green". None of those may appear, and these tests say so.
 *
 * THE OTHER TRAP IS THE DENOMINATOR. "4 of 15 controls flagged" means four of
 * the fifteen controls THIS PRODUCT MAPS, not four of the hundreds ISO 27001
 * contains. The two readings differ by an order of magnitude and only one is
 * true, so the page states which.
 */
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const compliance = vi.fn()

vi.mock('../api/client', () => ({
  compliance: (...a: unknown[]) => compliance(...a),
  ApiError: class ApiError extends Error {
    status: number
    constructor(status: number, message: string) { super(message); this.status = status }
  },
}))
vi.mock('../lib/title', () => ({ useTitle: () => {} }))

import { Compliance } from './Compliance'

const NOTE = 'A control carrying findings has open gaps. The absence of '
  + 'findings against a control is NOT an assertion of compliance with it.'

function control(over: Record<string, unknown> = {}) {
  return {
    id: 'A.8.8', name: 'Management of technical vulnerabilities',
    themes: ['Vulnerability & patch management'],
    crit: 3, high: 7, med: 2, low: 0, total: 12,
    ...over,
  }
}

function framework(over: Record<string, unknown> = {}) {
  return {
    id: 'iso27001', name: 'ISO/IEC 27001:2022', subtitle: 'Annex A controls',
    controls: [control()], controls_flagged: 1, total_controls: 15,
    mapped_findings: 12,
    ...over,
  }
}

function view(frameworks: unknown[]) {
  return { frameworks, findings_considered: 1369, note: NOTE }
}

function draw() {
  return render(<MemoryRouter><Compliance /></MemoryRouter>)
}

beforeEach(() => { vi.clearAllMocks() })

describe('the compliance posture screen', () => {
  it('lists every framework, not only the ones with findings', async () => {
    // Dropping an empty framework leaves a reader unable to tell "we map this
    // and found nothing" from "we do not map this at all".
    compliance.mockResolvedValue(view([
      framework(),
      framework({ id: 'gdpr', name: 'EU GDPR', controls: [],
                  controls_flagged: 0, total_controls: 3, mapped_findings: 0 }),
    ]))
    draw()
    expect(await screen.findByText('ISO/IEC 27001:2022')).toBeInTheDocument()
    expect(screen.getByText('EU GDPR')).toBeInTheDocument()
  })

  it('refuses to call an unmapped framework compliant', async () => {
    compliance.mockResolvedValue(view([
      framework({ id: 'gdpr', name: 'EU GDPR', controls: [],
                  controls_flagged: 0, total_controls: 3, mapped_findings: 0 }),
    ]))
    draw()
    expect(await screen.findByText(/not a statement that\s+its controls are met/))
      .toBeInTheDocument()
  })

  it('states the caveat before any number is read', async () => {
    compliance.mockResolvedValue(view([framework()]))
    draw()
    expect(await screen.findByText(/gap map, not a\s+certification/))
      .toBeInTheDocument()
    expect(screen.getByText(new RegExp('NOT an assertion of compliance')))
      .toBeInTheDocument()
  })

  it('says whose denominator it is', async () => {
    // "4 of 15" is four of the controls WE map. Read as four of ISO's
    // hundreds it would be a wildly different claim.
    compliance.mockResolvedValue(view([framework()]))
    draw()
    expect(await screen.findByText(/not of everything the framework contains/))
      .toBeInTheDocument()
    expect(screen.getByText(/1 of 15 mapped controls flagged/))
      .toBeInTheDocument()
  })

  it('shows no percentage anywhere', async () => {
    // The module forbids one. A screen is where it gets invented.
    compliance.mockResolvedValue(view([framework()]))
    const { container } = draw()
    await screen.findByText('ISO/IEC 27001:2022')
    expect(container.textContent).not.toMatch(/\d+\s?%/)
    expect(container.querySelector('progress')).toBeNull()
  })

  it('shows the controls behind a framework on request', async () => {
    compliance.mockResolvedValue(view([framework()]))
    draw()
    await userEvent.click(await screen.findByRole('button',
      { name: /Show the 1 control carrying findings/ }))
    expect(screen.getByText('A.8.8')).toBeInTheDocument()
    expect(screen.getByText('Management of technical vulnerabilities'))
      .toBeInTheDocument()
    // The themes are shown, because they are why the control was flagged.
    expect(screen.getByText('Vulnerability & patch management')).toBeInTheDocument()
  })

  it('draws a zero severity count as a dash rather than a nought', async () => {
    // A column of noughts reads as a measurement. This one means "none of
    // this severity", which the dash says without implying precision.
    compliance.mockResolvedValue(view([
      framework({ controls: [control({ crit: 0, high: 0, total: 4 })] }),
    ]))
    draw()
    await userEvent.click(await screen.findByRole('button', { name: /Show the 1/ }))
    expect(screen.getAllByText('—').length).toBeGreaterThanOrEqual(2)
  })
})
