/*
 * One NIST CSF 2.0 Function: its Categories, their findings, and — for the
 * Categories this product cannot assess — the reason no SAP export answers them.
 *
 * This is the screen where the Subcategories appear. They are listed as OUTCOMES
 * rather than scored, deliberately: CSWP 29 says the Subcategories "are not a
 * checklist of actions to perform", and per-Subcategory ticks would be exactly
 * that checklist, invented by us rather than measured. What we can honestly say
 * is which Category a finding is evidence against; below that granularity we
 * would be guessing, and a guess rendered as a tick is indistinguishable from a
 * measurement.
 */
import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router'

import { ApiError, csfFunction } from '../api/client'
import type { CsfCategory, CsfFunctionView, CsfStatus } from '../api/types'
import { useTitle } from '../lib/title'
import { statusLabel } from './Csf'
import { Landmark } from 'lucide-react'
import { CARD_TITLE as CARD_H3, KPI, KPI_NOTE } from '../lib/ui'

const CARD = 'rounded-lg border border-cardline bg-panel p-4'
const G4 = 'grid gap-3.5 [grid-template-columns:repeat(auto-fit,minmax(210px,1fr))]'
const H2 = 'text-[15px] font-semibold text-ink mt-7 mb-2.5'
const LINK = 'text-accent hover:underline'

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const

export function CsfFunction() {
  const { fn } = useParams()
  const [view, setView] = useState<CsfFunctionView | null>(null)
  const [failure, setFailure] = useState<string | null>(null)
  useTitle(view ? `${view.name} — NIST CSF` : null)

  useEffect(() => {
    let live = true
    setView(null)
    setFailure(null)
    csfFunction(fn ?? '')
      .then((v) => { if (live) setView(v) })
      .catch((e: unknown) => {
        if (!live) return
        const status = e instanceof ApiError ? e.status : 0
        setFailure(status === 404
          ? `“${fn}” is not one of the six CSF Functions.`
          : `This Function could not be loaded${status ? ` (HTTP ${status})` : ''}.`)
      })
    return () => { live = false }
  }, [fn])

  return (
    <>
      <p className="text-[12px] mb-1.5">
        <Link className={LINK} to="/csf">← NIST CSF 2.0</Link>
      </p>
      {failure && <div className="banner banner-bad" role="alert">{failure}</div>}
      {!failure && view === null && <p className="text-[13px] text-ink3">Loading…</p>}
      {view !== null && <Body view={view} />}
    </>
  )
}

/** A Category we have no measurement for, whichever reason applies.
 *
 *  THE BUG THIS NAMES. The page bucketed on `not_assessed` alone, so a Category
 *  in the newer `not_supplied` state was filed under "Assessed here" and told
 *  the reader "Assessed, and this run produced no findings against it" — while
 *  displaying the dashed "Export not supplied" chip an inch above. The product
 *  contradicted itself inside one card, and the HTML report for the same run
 *  printed an em dash and the opposite sentence.
 *
 *  Two states, two reasons, one fact: there is no number here. Bucketing on the
 *  fact rather than on one of the reasons is what stops the next state doing
 *  this again. */
const unmeasured = (status: CsfStatus) =>
  status === 'not_assessed' || status === 'not_supplied'

function Body({ view }: { view: CsfFunctionView }) {
  const notAssessed = view.categories.filter((c) => c.status === 'not_assessed')
  const notSupplied = view.categories.filter((c) => c.status === 'not_supplied')
  const assessed = view.categories.filter((c) => !unmeasured(c.status))
  return (
    <>
      <div className="flex items-center gap-2.5 mb-1">
        <span className={`csf csf-${view.id}`}>{view.id}</span>
        <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2 uppercase">
          <Landmark size={22} className="text-accent shrink-0" />
          {view.name}
        </h1>
      </div>
      {/* The outcome statement is NIST's, verbatim. It is the definition of the
          Function and belongs above our numbers, not beneath them. */}
      <p className="text-ink2 mb-5 max-w-[68ch]">{view.outcome}</p>

      <div className={G4}>
        <div className={`${CARD} csf-rail csf-rail-${view.id}`}>
          <h3 className={CARD_H3}>Open findings</h3>
          <div className={`${KPI} text-ink`}>{view.total}</div>
          <div className={KPI_NOTE}>evidence against this Function&rsquo;s outcomes</div>
        </div>
        <div className={CARD}>
          <h3 className={CARD_H3}>Categories assessed</h3>
          <div className={`${KPI} text-ink`}>
            {view.categories_assessed}<span className="text-ink3 text-[19px]"> / {view.categories_total}</span>
          </div>
          {/* Both kinds of absence, named separately: one is a boundary of the
              product, the other is a missing upload the customer can fix. */}
          <div className={KPI_NOTE}>
            {notAssessed.length > 0 && `${notAssessed.length} outside this product’s evidence`}
            {notAssessed.length > 0 && notSupplied.length > 0 && ' · '}
            {notSupplied.length > 0 && `${notSupplied.length} awaiting an export`}
            {notAssessed.length === 0 && notSupplied.length === 0
              && 'all of them are within reach of an export'}
          </div>
        </div>
        <div className={CARD}>
          <h3 className={CARD_H3}>Categories with findings</h3>
          <div className={`${KPI} text-ink`}>{view.categories_with_findings}</div>
          <div className={KPI_NOTE}>have at least one open finding</div>
        </div>
        <div className={CARD}>
          <h3 className={CARD_H3}>Subcategories</h3>
          <div className={`${KPI} text-ink`}>{view.subcategories_total}</div>
          <div className={KPI_NOTE}>published outcomes in this Function</div>
        </div>
      </div>

      <h2 className={H2}>Assessed here</h2>
      {assessed.length === 0 && (
        /* TWO DIFFERENT EMPTY STATES, and the original said the first one about
           both. A Function whose Categories are all `not_supplied` IS assessable
           from an SAP export — the export simply was not supplied — so telling
           the reader none of it "can be assessed" is false, and false in the
           direction that stops them fixing it. */
        <div className="banner banner-info">
          {notSupplied.length > 0
            ? <>Nothing that feeds this Function&rsquo;s Categories ran in the scans
                you can see, so none of them has a result yet. They are assessable
                from an SAP export &mdash; see below for which are waiting on one.</>
            : <>None of this Function&rsquo;s Categories can be assessed from an SAP
                configuration export. See below for what each one asks and why.</>}
        </div>
      )}
      <div className="grid gap-3.5">
        {assessed.map((c) => <CategoryCard key={c.id} cat={c} />)}
      </div>

      {notSupplied.length > 0 && (
        <>
          <h2 className={H2}>Not assessed in this scan</h2>
          <p className="text-[13px] text-ink2 mb-2.5 max-w-[80ch]">
            These Categories are within reach of an SAP export — nothing that
            feeds them ran in the scans you can see, so their absence of findings
            is unexamined rather than clean. Supplying the missing exports and
            re-running is all it takes.
          </p>
          <div className="grid gap-3.5">
            {notSupplied.map((c) => <CategoryCard key={c.id} cat={c} />)}
          </div>
        </>
      )}

      {notAssessed.length > 0 && (
        <>
          <h2 className={H2}>Not assessed by this product</h2>
          <p className="text-[12px] text-ink2 mb-2.5 max-w-[74ch]">
            These outcomes are real and they matter. This scanner simply produces
            no evidence about them — they live in policies, registers, training
            records and incident logs rather than in system configuration. They
            are drawn dashed so they are never mistaken for a clean result, and
            they need a different source of assurance.
          </p>
          <div className="grid gap-3.5">
            {notAssessed.map((c) => <CategoryCard key={c.id} cat={c} />)}
          </div>
        </>
      )}

      {view.reference && (
        <p className="text-[12px] text-ink3 mt-6">
          Outcome and Category text: {view.reference}
          {view.doi && <> · <a className={LINK} href={view.doi} target="_blank" rel="noreferrer noopener">{view.doi}</a></>}
        </p>
      )}
    </>
  )
}

function CategoryCard({ cat }: { cat: CsfCategory }) {
  return (
    <div className={`${CARD} csf-card-${cat.status}`}>
      <div className="flex flex-wrap items-center gap-2 mb-1.5">
        <span className="font-mono text-[12px] font-semibold text-ink">{cat.id}</span>
        <span className="text-[13px] font-semibold text-ink">{cat.name}</span>
        <span className={`csf-state csf-state-${cat.status}`}>{statusLabel(cat.status)}</span>
        {!unmeasured(cat.status) && (
          <span className="ml-auto font-mono text-[13px] text-ink">
            {cat.total} finding{cat.total === 1 ? '' : 's'}
          </span>
        )}
      </div>
      <p className="text-[12px] text-ink2 leading-snug mb-2.5 max-w-[80ch]">{cat.description}</p>

      {unmeasured(cat.status) ? (
        <p className="text-[12px] text-ink3 border-t border-line pt-2.5 m-0">
          <strong className="text-ink2">Why there is nothing here: </strong>
          {cat.status === 'not_supplied'
            ? 'No module feeding this Category ran in the scans you can see, so '
              + 'the absence of findings here is unexamined rather than clean.'
            : cat.reason}
        </p>
      ) : (
        <>
          <div className="flex flex-wrap gap-1.5 mb-2.5">
            {SEVERITIES.map((s) => (cat.counts[s] ?? 0) > 0 && (
              <span key={s} className={`pill sev-${s}`}>{cat.counts[s]} {s.toLowerCase()}</span>
            ))}
            {cat.total === 0 && (
              <span className="text-[12px] text-ink2">
                Assessed, and this run produced no findings against it.
              </span>
            )}
          </div>
          {cat.themes.length > 0 && (
            <p className="text-[12px] text-ink3 m-0">
              Evidence comes from: {cat.themes.join(' · ')}
            </p>
          )}
        </>
      )}

      <details className="mt-2.5">
        <summary className="text-[12px] text-ink2 cursor-pointer select-none">
          {cat.subcategories.length} Subcategory outcome{cat.subcategories.length === 1 ? '' : 's'}
        </summary>
        <ul className="mt-2 border-t border-line pt-2 grid gap-1.5">
          {cat.subcategories.map((s) => (
            <li key={s.id} className="text-[12px] text-ink2 leading-snug">
              <span className="font-mono text-ink3 mr-1.5">{s.id}</span>
              {s.text}
            </li>
          ))}
        </ul>
        <p className="text-[11px] text-ink3 mt-2 m-0">
          Listed, not scored. CSF 2.0 states the Subcategories &ldquo;are not a
          checklist of actions to perform&rdquo;, and a per-Subcategory tick would
          be our invention rather than a measurement.
        </p>
      </details>
    </div>
  )
}
