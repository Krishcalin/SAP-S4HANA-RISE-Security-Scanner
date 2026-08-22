import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { CheckDetail } from './CheckDetail'
import type { CheckDoc } from '../api/types'

/**
 * Where a check's prose came from, and why the page has to say so.
 *
 * 352 of 714 published check ids had no narrative and this page said so on every
 * one of them. 198 of those were describable from material the product already
 * shipped — 127 from hand-written FAMILY entries that an exact-match lookup had
 * never reached, and 71 from the rule tables that generate the checks.
 *
 * THE RISK IN READING THEM IS OVERSTATEMENT. A family narrative is a page about
 * sixteen patterns, not about this one. A rule description is two sentences about
 * a regex. Both are far better than "no published description" and neither is a
 * page somebody wrote about this check — so the page labels the weaker two and
 * says nothing at all when the narrative really was written for this id, which is
 * the default a reader is entitled to assume.
 */

vi.mock('../api/client', () => ({
  checkDoc: vi.fn(),
  ApiError: class ApiError extends Error {
    status: number
    constructor(status: number, message: string) {
      super(message)
      this.status = status
    }
  },
}))

vi.mock('../lib/title', () => ({ useTitle: () => {} }))

import { checkDoc as fetchCheckDoc } from '../api/client'

function doc(over: Partial<CheckDoc> = {}): CheckDoc {
  return {
    check_id: 'LOG-AUD-001',
    category: 'Logging, Monitoring & IR',
    module: 'log_monitoring',
    module_reads: ['audit_config'],
    documented: true,
    doc_source: 'knowledge_base',
    doc_detail: null,
    doc_specific: null,
    risk: 'The Security Audit Log is SAP’s single most important forensic control.',
    mitigation: '1. Open RSAU_CONFIG and build the audit configuration.',
    requirements: [],
    paths: [],
    ...over,
  }
}

function renderAt(id: string) {
  return render(
    <MemoryRouter initialEntries={[`/checks/${id}`]}>
      <Routes><Route path="/checks/:id" element={<CheckDetail />} /></Routes>
    </MemoryRouter>,
  )
}

describe('CheckDetail — provenance of the prose', () => {
  beforeEach(() => vi.clearAllMocks())

  it('says nothing when the narrative was written for this check', async () => {
    vi.mocked(fetchCheckDoc).mockResolvedValue(doc())
    renderAt('LOG-AUD-001')
    await waitFor(() => expect(screen.getByText(/forensic control/)).toBeTruthy())
    // No caveat banner: an unqualified narrative is the default, and labelling
    // it would make the reader doubt the one source that needs no caveat.
    expect(screen.queryByText(/family, not this single rule/)).toBeNull()
    expect(screen.queryByText(/rule that defines this check/)).toBeNull()
  })

  it('says when the narrative is about the family rather than this rule', async () => {
    vi.mocked(fetchCheckDoc).mockResolvedValue(doc({
      check_id: 'ABAP-SQLI-001',
      doc_source: 'knowledge_base_family',
      doc_detail: 'ABAP-SQLI',
      doc_specific: 'A SELECT uses a dynamic WHERE clause supplied via a variable.',
      risk: 'An attacker-controlled value is concatenated into an Open SQL statement.',
    }))
    renderAt('ABAP-SQLI-001')
    // The banner names the family. `ABAP-SQLI-001` is also the page heading, so
    // scope the match to the banner rather than to the whole document.
    const banner = await waitFor(() =>
      screen.getByText(/family, not this single rule/).closest('.banner'))
    expect(banner?.textContent).toContain('ABAP-SQLI')
  })

  it('shows what this rule matches above what the family is about', async () => {
    vi.mocked(fetchCheckDoc).mockResolvedValue(doc({
      check_id: 'ABAP-SQLI-001',
      doc_source: 'knowledge_base_family',
      doc_detail: 'ABAP-SQLI',
      doc_specific: 'A SELECT uses a dynamic WHERE clause supplied via a variable.',
      risk: 'An attacker-controlled value is concatenated into an Open SQL statement.',
    }))
    renderAt('ABAP-SQLI-001')
    // Somebody arriving from a finding wants to know what fired. The family
    // narrative cannot tell them — it is about all sixteen patterns.
    await waitFor(() =>
      expect(screen.getByText(/What this rule matches/)).toBeTruthy())
    expect(screen.getByText(/dynamic WHERE clause/)).toBeTruthy()
  })

  it('says when the text is a rule definition rather than a narrative', async () => {
    vi.mocked(fetchCheckDoc).mockResolvedValue(doc({
      check_id: 'WDISP-001',
      doc_source: 'rule_definition',
      doc_detail: 'Web Dispatcher rule',
      doc_specific: null,
      risk: 'The HTTP server header names the product and often its version.',
    }))
    renderAt('WDISP-001')
    await waitFor(() =>
      expect(screen.getByText(/rule that defines this check/)).toBeTruthy())
    expect(screen.getByText(/Web Dispatcher rule/)).toBeTruthy()
    // No duplicate: where the rule IS the narrative, printing its description
    // again as a lead line would show the same sentences twice.
    expect(screen.queryByText(/What this rule matches/)).toBeNull()
  })

  it('still says plainly when nothing describes the check', async () => {
    vi.mocked(fetchCheckDoc).mockResolvedValue(doc({
      check_id: 'ARA-BASIS-01',
      documented: false,
      doc_source: null,
      doc_detail: null,
      doc_specific: null,
      risk: null,
      mitigation: null,
    }))
    renderAt('ARA-BASIS-01')
    // 154 checks still land here, and the page must not have quietly stopped
    // admitting it just because most of the gap closed.
    await waitFor(() =>
      expect(screen.getByText(/No published description/)).toBeTruthy())
  })
})
