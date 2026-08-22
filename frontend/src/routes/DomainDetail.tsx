/*
 * One security domain: what it covers, what this product can see in it, and the
 * findings that landed there.
 *
 * The scope sentence is rendered ABOVE the findings, not below. A reader who
 * meets a list of forty findings under "Interface Traffic Monitoring" and only
 * afterwards learns we do not see traffic has already formed the wrong idea.
 */
import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router'

import { ApiError, domain as fetchDomain } from '../api/client'
import type { SecurityDomain } from '../api/types'
import { useTitle } from '../lib/title'
import { stateChip } from './Domains'
import { LayoutGrid } from 'lucide-react'

const CARD = 'rounded-lg border border-line bg-panel p-4'
const CARD_H3 = 'text-[12px] font-semibold uppercase tracking-[.06em] text-ink3 mb-3'
const KPI = 'text-[30px] font-semibold tracking-[-.02em] leading-[1.1]'
const KPI_NOTE = 'text-ink2 text-[12px] mt-1.5'
const G4 = 'grid gap-3.5 [grid-template-columns:repeat(auto-fit,minmax(200px,1fr))]'
const H2 = 'text-[15px] font-semibold text-ink mt-7 mb-2.5'
const TH = 'text-left text-[11px] font-semibold uppercase tracking-[.05em] text-ink3 px-2.5 py-2 border-b border-line'
const TD = 'px-2.5 py-2.5 border-b border-line align-top'
const TABLE_CARD = 'rounded-lg border border-line bg-panel overflow-x-auto'
const LINK = 'text-accent hover:underline'
const EMPTY = 'p-9 text-center text-ink2'

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const

const REACH_SENTENCE: Record<string, string> = {
  full: 'This product assesses this domain in full.',
  partial: 'This product assesses part of this domain.',
  config_only: 'This product assesses the configuration behind this domain, not the activity.',
  none: 'This product does not assess this domain.',
}

export function DomainDetail() {
  const { id } = useParams()
  const [view, setView] = useState<SecurityDomain | null>(null)
  const [failure, setFailure] = useState<string | null>(null)
  useTitle(view ? view.label : null)

  useEffect(() => {
    let live = true
    setView(null)
    setFailure(null)
    fetchDomain(id ?? '')
      .then((v) => { if (live) setView(v) })
      .catch((e: unknown) => {
        if (!live) return
        const status = e instanceof ApiError ? e.status : 0
        setFailure(status === 404
          ? `“${id}” is not one of the twelve domains.`
          : `This domain could not be loaded${status ? ` (HTTP ${status})` : ''}.`)
      })
    return () => { live = false }
  }, [id])

  return (
    <>
      <p className="text-[12px] mb-1.5">
        <Link className={LINK} to="/domains">← Security Domains</Link>
      </p>
      {failure && <div className="banner banner-bad" role="alert">{failure}</div>}
      {!failure && view === null && <p className="text-[13px] text-ink3">Loading…</p>}
      {view !== null && <Body d={view} />}
    </>
  )
}

function Body({ d }: { d: SecurityDomain }) {
  const chip = stateChip(d)
  const findings = d.findings ?? []
  const covered = d.reach !== 'none'

  return (
    <>
      <div className="flex flex-wrap items-center gap-2.5 mb-1">
        <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2">
          <LayoutGrid size={22} className="text-accent shrink-0" />
          {d.label}
        </h1>
        <span className={`csf-state ${chip.cls}`}>{chip.text}</span>
      </div>

      {/* WHAT WE CAN SEE, BEFORE WHAT WE FOUND. A reader who meets forty findings
          under a monitoring heading and only then learns we do not monitor has
          already formed the wrong idea, and a correction underneath arrives too
          late to undo it. */}
      <p className="text-ink2 mb-1 max-w-[80ch]">
        <strong>{REACH_SENTENCE[d.reach]}</strong>
      </p>
      {d.scope && <p className="dom-scope mb-5 max-w-[80ch]">{d.scope}</p>}
      {!d.scope && d.blurb && <p className="text-ink2 mb-5 max-w-[80ch]">{d.blurb}</p>}

      {!covered ? (
        <div className="banner banner-info">
          There are no findings here, and there never will be — this is a boundary
          of the product rather than a result about your estate. Nothing on this
          page should be read as assurance.
        </div>
      ) : (
        <>
          <div className={G4}>
            <div className={`${CARD} dom-rail dom-rail-${d.reach}`}>
              <h3 className={CARD_H3}>Open findings</h3>
              <div className={`${KPI} text-ink`}>{d.total}</div>
              <div className={KPI_NOTE}>
                {d.state === 'not_supplied'
                  ? 'the exports behind this domain were not supplied'
                  : d.total === 0 ? 'assessed, and nothing found' : 'in this domain'}
              </div>
            </div>
            {SEVERITIES.filter((s) => (d.counts[s] ?? 0) > 0).slice(0, 3).map((s) => (
              <div key={s} className={CARD}>
                <h3 className={CARD_H3}>{s.toLowerCase()}</h3>
                <div className={`${KPI} text-ink`}>{d.counts[s]}</div>
                <div className={KPI_NOTE}>severity</div>
              </div>
            ))}
          </div>

          <h2 className={H2}>What feeds this domain</h2>
          <p className="text-[12px] text-ink2 mb-2.5">
            {(d.categories_detail?.length ? d.categories_detail : d.categories)
              .join(' · ') || 'no categories'}
          </p>

          <h2 className={H2}>
            Findings
            <Link className="ml-2.5 text-[12px] font-normal text-accent hover:underline"
                  to={`/findings?domain=${encodeURIComponent(d.id)}`}>
              Open in the triage queue →
            </Link>
          </h2>
          <div className={TABLE_CARD}>
            <table className="w-full border-collapse">
              <thead>
                <tr>
                  <th className={TH}>Check</th>
                  <th className={TH}>Severity</th>
                  <th className={TH}>Title</th>
                  <th className={TH}>System</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f) => (
                  <tr key={f.id} className="hover:bg-panel2">
                    <td className={`${TD} font-mono text-[12px] whitespace-nowrap`}>
                      <Link className={LINK} to={`/findings/${f.id}`}>{f.check_id}</Link>
                    </td>
                    <td className={TD}>
                      <span className={`pill sev-${f.severity ?? 'INFO'}`}>{f.severity}</span>
                    </td>
                    <td className={TD}>{f.title}</td>
                    <td className={`${TD} font-mono text-[12px] text-ink2`}>
                      {f.sid ?? '—'}
                    </td>
                  </tr>
                ))}
                {findings.length === 0 && (
                  <tr>
                    <td className={EMPTY} colSpan={4}>
                      {d.state === 'not_supplied'
                        ? 'No findings, because the exports this domain reads were '
                          + 'never supplied. That is not the same as nothing being wrong.'
                        : 'Assessed, and this run produced no findings here.'}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
            {findings.length >= 500 && (
              <p className="text-[12px] text-ink3 px-3.5 py-2.5 m-0">
                Showing the first 500 by severity. The full set is in{' '}
                <Link className={LINK} to={`/findings?domain=${encodeURIComponent(d.id)}`}>
                  the triage queue
                </Link>, which pages through all {d.total}.
              </p>
            )}
          </div>
        </>
      )}
    </>
  )
}
