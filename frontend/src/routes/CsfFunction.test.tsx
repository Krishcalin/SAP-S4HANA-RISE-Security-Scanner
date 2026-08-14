/*
 * Copyright (c) 2026 Krishnendu De. All Rights Reserved.
 *
 * Author : Krishnendu De
 * Coding Assistance : Claude Code
 * Code Security Assistance : Code QL
 */

import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { CsfFunction } from './CsfFunction'
import type { CsfCategory, CsfFunctionView, CsfStatus } from '../api/types'

/**
 * The first render test in this console, and it exists for a specific defect.
 *
 * /csf/<fn> bucketed its Categories on `not_assessed` alone. A Category in the
 * newer `not_supplied` state therefore appeared under the heading "Assessed
 * here" and told the reader "Assessed, and this run produced no findings against
 * it" — while displaying the dashed "Export not supplied" chip an inch above it.
 * One card, two opposite claims about the same Category, and the HTML report for
 * the same run printed a third thing.
 *
 * It type-checked perfectly. It shipped. The Python-side guard written alongside
 * the fix asserts that a PREDICATE EXISTS in the source, which is a proxy for the
 * behaviour and not the behaviour — and it says so in its own docstring, and
 * instructs its own deletion in favour of this file.
 *
 * WHAT THIS ASSERTS IS WHAT A READER SEES. Not a state name, not a class name —
 * the sentences. Every regression in this class has been a screen printing a
 * reassuring sentence over an absence of evidence, so the sentences are the
 * thing to hold.
 */

vi.mock('../api/client', () => ({
  csfFunction: vi.fn(),
  ApiError: class ApiError extends Error {
    status: number
    constructor(status: number, message: string) {
      super(message)
      this.status = status
    }
  },
}))

vi.mock('../lib/title', () => ({ useTitle: () => {} }))

const category = (
  id: string, status: CsfStatus, extra: Partial<CsfCategory> = {},
): CsfCategory => ({
  id,
  function: 'DE',
  name: `Category ${id}`,
  description: `What ${id} asks for`,
  status,
  themes: status === 'not_assessed' ? [] : ['logging'],
  reason: status === 'not_assessed' ? 'No SAP export answers this outcome.' : null,
  counts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
  total: 0,
  subcategories: [{ id: `${id}-01`, text: 'An outcome sentence.' }],
  ...extra,
})

const view = (categories: CsfCategory[]): CsfFunctionView => ({
  id: 'DE',
  name: 'Detect',
  outcome: 'Possible cybersecurity attacks and compromises are found and analysed.',
  counts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
  total: categories.reduce((n, c) => n + c.total, 0),
  categories,
  categories_total: categories.length,
  categories_assessed: categories.filter((c) => c.status !== 'not_assessed').length,
  categories_with_findings: categories.filter((c) => c.total > 0).length,
  subcategories_total: categories.length,
  reference: 'NIST CSWP 29',
})

async function renderFunction(v: CsfFunctionView) {
  const { csfFunction } = await import('../api/client')
  vi.mocked(csfFunction).mockResolvedValue(v)
  render(
    <MemoryRouter initialEntries={['/csf/DE']}>
      <Routes>
        <Route path="/csf/:fn" element={<CsfFunction />} />
      </Routes>
    </MemoryRouter>,
  )
  await waitFor(() => expect(screen.getByText('Detect')).toBeInTheDocument())
}

describe('a Category whose export never arrived', () => {
  beforeEach(() => vi.clearAllMocks())

  it('is never filed under "Assessed here"', async () => {
    await renderFunction(view([category('DE.CM', 'not_supplied')]))
    // Asserted by DOM ORDER rather than by containment: the headings and the
    // card grids are siblings, so there is no wrapper to scope a query to, and
    // `parentElement` is the whole page. Order is what a reader actually sees.
    const heading = screen.getByRole('heading', { name: 'Not assessed in this scan' })
    const card = screen.getByText('Category DE.CM')
    expect(heading.compareDocumentPosition(card)
      & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()

    // And the "Assessed here" section says what is true of an unsupplied
    // Function, rather than that it cannot be assessed at all.
    expect(screen.getByText(/They are assessable from an SAP export/))
      .toBeInTheDocument()
    expect(screen.queryByText(/None of this Function.s Categories can be assessed/))
      .toBeNull()
  })

  it('gets its own heading, not the product-boundary one', async () => {
    await renderFunction(view([category('DE.CM', 'not_supplied')]))
    expect(screen.getByRole('heading', { name: 'Not assessed in this scan' }))
      .toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'Not assessed by this product' }))
      .toBeNull()
  })

  it('never tells the reader it was assessed and clean', async () => {
    await renderFunction(view([category('DE.CM', 'not_supplied')]))
    expect(screen.queryByText(/Assessed, and this run produced no findings/))
      .toBeNull()
    // The phrase appears twice on purpose — once introducing the section, once
    // inside each card — so this asks for all of them rather than one.
    expect(screen.getAllByText(/unexamined rather than clean/).length)
      .toBeGreaterThan(0)
  })

  it('shows no finding count, because 0 would read as a measurement', async () => {
    await renderFunction(view([category('DE.CM', 'not_supplied')]))
    expect(screen.queryByText('0 findings')).toBeNull()
  })

  it('makes no clean claim anywhere on the page', async () => {
    await renderFunction(view([
      category('DE.CM', 'not_supplied'),
      category('DE.AE', 'not_supplied'),
    ]))
    expect(document.body).toMakeNoCleanClaim()
  })
})

describe('the states that are not this one', () => {
  beforeEach(() => vi.clearAllMocks())

  it('still separates a product boundary from a missing upload', async () => {
    await renderFunction(view([
      category('DE.CM', 'not_supplied'),
      category('DE.AE', 'not_assessed'),
    ]))
    expect(screen.getByRole('heading', { name: 'Not assessed in this scan' }))
      .toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Not assessed by this product' }))
      .toBeInTheDocument()
  })

  it('still lets a Category that was assessed and found nothing say so', async () => {
    await renderFunction(view([category('DE.CM', 'clear')]))
    expect(screen.getByText(/Assessed, and this run produced no findings/))
      .toBeInTheDocument()
  })

  it('still reports findings where there are findings', async () => {
    await renderFunction(view([
      category('DE.CM', 'assessed', {
        total: 3, counts: { CRITICAL: 1, HIGH: 2, MEDIUM: 0, LOW: 0, INFO: 0 },
      }),
    ]))
    expect(screen.getByText('3 findings')).toBeInTheDocument()
  })
})
