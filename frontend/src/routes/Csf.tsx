/*
 * NIST Cybersecurity Framework (CSF) 2.0 — the whole Core, one screen.
 *
 * WHAT THIS SCREEN REFUSES TO DO, AND WHY IT MATTERS MOST
 * It shows no compliance percentage. modules/compliance_mapping.py forbids one
 * ("we see the findings, not the control environment") and Coverage.tsx already
 * sets the precedent of counts without a traffic light. A "78% CSF compliant"
 * ring would be the most clickable thing here and the least defensible.
 *
 * And it never renders a Category we cannot assess as a Category with no
 * problems. Ten of the 22 are programme outcomes — policy, training, oversight,
 * incident communications — that no SAP export answers. They are drawn dashed
 * and dimmed, each carrying the reason it is out of reach, because a green tick
 * against an outcome nobody examined is worse than no tile at all.
 */
import { useEffect, useState } from 'react'
import { Link } from 'react-router'

import { ApiError, csf } from '../api/client'
import type { CsfFunctionView, CsfStatus, CsfView } from '../api/types'
import { useTitle } from '../lib/title'
import { Landmark } from 'lucide-react'
import { CARD_TITLE as CARD_H3, KPI, KPI_NOTE } from '../lib/ui'

const CARD = 'rounded-lg border border-cardline bg-panel p-4'
const G4 = 'grid gap-3.5 [grid-template-columns:repeat(auto-fit,minmax(210px,1fr))]'
const G3 = 'grid gap-3.5 [grid-template-columns:repeat(auto-fit,minmax(268px,1fr))]'
const H2 = 'text-[15px] font-semibold text-ink mt-7 mb-2.5'
const TH = 'text-left text-[11px] font-semibold uppercase tracking-[.05em] text-ink3 px-2.5 py-2 border-b border-line'
const TD = 'px-2.5 py-2.5 border-b border-line align-top'
const TABLE_CARD = 'rounded-lg border border-cardline bg-panel overflow-x-auto'
const LINK = 'text-accent hover:underline'

/** The Function's route slug. /csf/PR would work too; the word reads better. */
const SLUG: Record<string, string> = {
  GV: 'govern', ID: 'identify', PR: 'protect',
  DE: 'detect', RS: 'respond', RC: 'recover',
}

export function statusLabel(status: CsfStatus): string {
  if (status === 'clear') return 'No findings'
  if (status === 'not_assessed') return 'Not assessed'
  // "We would have looked and the export never arrived" is the customer's to
  // act on, unlike `not_assessed`, which is ours. Worded as the thing they can
  // do something about rather than as a status code.
  if (status === 'not_supplied') return 'Export not supplied'
  return 'Findings'
}

export function Csf() {
  useTitle('NIST CSF 2.0')
  const [view, setView] = useState<CsfView | null>(null)
  const [failure, setFailure] = useState<string | null>(null)

  useEffect(() => {
    let live = true
    csf()
      .then((v) => { if (live) setView(v) })
      .catch((e: unknown) => {
        if (!live) return
        const status = e instanceof ApiError ? e.status : 0
        setFailure(status === 403
          ? 'Your account is not permitted to see the framework view.'
          : `The CSF view could not be loaded${status ? ` (HTTP ${status})` : ''}.`)
      })
    return () => { live = false }
  }, [])

  return (
    <>
      <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2 mb-1">
        <Landmark size={22} className="text-accent shrink-0" />
        NIST Cybersecurity Framework 2.0
      </h1>
      <p className="text-ink2 mb-5">
        Your open findings, arranged by the outcome each one is evidence against.
      </p>

      {failure && <div className="banner banner-bad" role="alert">{failure}</div>}
      {!failure && view === null && <p className="text-[13px] text-ink3">Loading…</p>}
      {view !== null && <Body view={view} />}
    </>
  )
}

function Body({ view }: { view: CsfView }) {
  const t = view.totals
  return (
    <>
      {/* The scope statement leads, because everything below is read differently
          once you know 10 of 22 Categories are outside this product's reach. */}
      <div className="banner banner-info">
        This product assesses <strong>{t.categories_assessable} of the {t.categories} CSF
        Categories</strong>. The other {t.categories_not_assessed} describe governance,
        training and incident-response outcomes that no SAP configuration export
        reveals — they are shown below, dashed, with the reason for each. Nothing
        here is a statement that you comply with a Category; a finding is evidence
        against an outcome, and the absence of findings is not evidence for one.
      </div>

      <div className={G4}>
        <div className={CARD}>
          <h3 className={CARD_H3}>Open findings</h3>
          <div className={`${KPI} text-ink`}>{t.findings}</div>
          <div className={KPI_NOTE}>across every system you can see</div>
        </div>
        <div className={CARD}>
          <h3 className={CARD_H3}>Placed on the Core</h3>
          <div className={`${KPI} text-ink`}>{t.mapped}</div>
          <div className={KPI_NOTE}>
            {t.unmapped === 0
              ? 'every finding maps to at least one outcome'
              : `${t.unmapped} could not be placed — see below`}
          </div>
        </div>
        <div className={CARD}>
          <h3 className={CARD_H3}>Categories assessed</h3>
          <div className={`${KPI} text-ink`}>{t.categories_assessable}<span className="text-ink3 text-[19px]"> / {t.categories}</span></div>
          <div className={KPI_NOTE}>{t.categories_not_assessed} outside this product&rsquo;s evidence</div>
        </div>
        <div className={CARD}>
          <h3 className={CARD_H3}>Subcategories</h3>
          <div className={`${KPI} text-ink`}>{t.subcategories}</div>
          <div className={KPI_NOTE}>the published Core, in full</div>
        </div>
      </div>

      <h2 className={H2}>The six Functions</h2>
      <div className={G3}>
        {view.functions.map((f) => <FunctionTile key={f.id} fn={f} />)}
      </div>

      <h2 className={H2}>Every Category</h2>
      <div className={TABLE_CARD}>
        <table className="w-full border-collapse">
          <thead>
            <tr>
              <th className={TH}>Category</th>
              <th className={TH}>Name</th>
              <th className={TH}>State</th>
              <th className={`${TH} text-right`}>Findings</th>
              <th className={TH}>What it covers here</th>
            </tr>
          </thead>
          <tbody>
            {view.functions.flatMap((f) => f.categories.map((c) => (
              <tr key={c.id} className="hover:bg-panel2">
                <td className={`${TD} font-mono text-[12px] whitespace-nowrap`}>
                  <span className={`csf csf-${c.function} mr-2`}>{c.function}</span>
                  <Link className={LINK} to={`/csf/${SLUG[c.function]}`}>{c.id}</Link>
                </td>
                <td className={TD}>{c.name}</td>
                <td className={TD}>
                  <span className={`csf-state csf-state-${c.status}`}>{statusLabel(c.status)}</span>
                </td>
                <td className={`${TD} text-right font-mono`}>
                  {c.status === 'not_assessed' ? <span className="text-ink3">—</span> : c.total}
                </td>
                <td className={`${TD} text-[12px] text-ink2`}>
                  {c.status === 'not_assessed'
                    ? <span className="text-ink3">{c.reason}</span>
                    : c.themes.join(' · ')}
                </td>
              </tr>
            )))}
          </tbody>
        </table>
        <p className="text-[12px] text-ink3 px-3.5 py-2.5 m-0">
          A finding is evidence against more than one outcome, so it can appear
          under several Categories. Each Category counts it once, and a Function
          counts it once across its Categories — the totals are findings, never
          attributions.
        </p>
      </div>

      {t.unmapped > 0 && (
        <>
          <h2 className={H2}>Findings this view could not place</h2>
          <div className={TABLE_CARD}>
            <table className="w-full border-collapse">
              <thead>
                <tr>
                  <th className={TH}>Finding category</th>
                  <th className={`${TH} text-right`}>Findings</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(t.unmapped_categories).map(([name, n]) => (
                  <tr key={name} className="hover:bg-panel2">
                    <td className={TD}>{name}</td>
                    <td className={`${TD} text-right font-mono`}>{n}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="text-[12px] text-ink3 px-3.5 py-2.5 m-0">
              These are real findings that reach no CSF outcome, because their
              category has no theme mapping. They are listed rather than dropped:
              silently discarding them would make the numbers above look like the
              whole picture. They remain on <Link className={LINK} to="/findings">Findings</Link>.
            </p>
          </div>
        </>
      )}

      <p className="text-[12px] text-ink3 mt-6">
        {view.framework} · {view.reference} ·{' '}
        <a className={LINK} href={view.doi} target="_blank" rel="noreferrer noopener">{view.doi}</a>
        {' '}· A U.S. Government work. The Core is reproduced for navigation;
        outcome text is NIST&rsquo;s.
      </p>
    </>
  )
}

function FunctionTile({ fn }: { fn: CsfFunctionView }) {
  const crit = fn.counts.CRITICAL ?? 0
  const high = fn.counts.HIGH ?? 0
  const notAssessed = fn.categories_total - fn.categories_assessed
  return (
    <Link
      to={`/csf/${SLUG[fn.id]}`}
      className={`${CARD} csf-rail csf-rail-${fn.id} block no-underline hover:bg-panel2`}
    >
      <div className="flex items-center gap-2 mb-2">
        <span className={`csf csf-${fn.id}`}>{fn.id}</span>
        <span className="text-[13px] font-semibold text-ink uppercase tracking-[.06em]">{fn.name}</span>
      </div>
      <p className="text-[12px] text-ink2 leading-snug mb-3 min-h-[2.6em]">{fn.outcome}</p>
      <div className="flex items-baseline gap-2">
        <span className={`${KPI} text-ink`}>{fn.total}</span>
        <span className="text-[12px] text-ink2">open finding{fn.total === 1 ? '' : 's'}</span>
      </div>
      <div className="flex flex-wrap gap-1.5 mt-2.5">
        {crit > 0 && <span className="pill sev-CRITICAL">{crit} critical</span>}
        {high > 0 && <span className="pill sev-HIGH">{high} high</span>}
        {fn.total === 0 && fn.categories_assessed > 0 && (
          <span className="csf-state csf-state-clear">No findings</span>
        )}
      </div>
      <div className={KPI_NOTE}>
        {fn.categories_assessed} of {fn.categories_total} categories assessed
        {notAssessed > 0 && <> · <span className="text-ink3">{notAssessed} not assessed</span></>}
      </div>
    </Link>
  )
}
