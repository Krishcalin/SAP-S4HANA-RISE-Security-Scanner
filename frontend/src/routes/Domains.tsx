/*
 * The twelve security domains, in the vocabulary a buyer already uses.
 *
 * WHY THE LABELS ARE NOT OURS
 * These names closely mirror a commercial competitor's module list, deliberately:
 * a reader holding an RFP checklist can match them line for line. That is the only
 * reason to adopt somebody else's taxonomy, and renaming the tiles would forfeit
 * it — so the labels are verbatim and the honesty lives one line below, in `scope`.
 *
 * WHAT THIS SCREEN REFUSES TO DO
 * Twelve tiles each showing a number would assert twelve capabilities, and four of
 * them would be false. This is a point-in-time configuration assessment: it does
 * not monitor events, watch traffic, model behaviour, or block an exploit.
 *
 * So every tile carries two different facts, drawn differently on purpose:
 *   REACH  what this product can EVER see here. A property of the product, fixed,
 *          identical for every customer. Drawn as a rail on the tile's edge.
 *   STATE  what THIS run found. Drawn as a worded pill.
 *
 * A reader who cannot separate them reads "configuration only" as a result and
 * "clear" as a capability. The domain we do not cover at all is dashed and grey,
 * never red: a product boundary is not a problem in the customer's estate.
 */
import { useEffect, useState } from 'react'
import { Link } from 'react-router'

import { ApiError, domains as fetchDomains } from '../api/client'
import type { DomainReach, DomainsView, SecurityDomain } from '../api/types'
import { useTitle } from '../lib/title'
import { LayoutGrid } from 'lucide-react'

const CARD = 'rounded-lg border border-cardline bg-panel p-4'
const KPI = 'text-[30px] font-semibold tracking-[-.02em] leading-[1.1]'
const G3 = 'grid gap-3.5 [grid-template-columns:repeat(auto-fit,minmax(300px,1fr))]'
const H2 = 'text-[15px] font-semibold text-ink mt-7 mb-2.5'
const TH = 'text-left text-[11px] font-semibold uppercase tracking-[.05em] text-ink3 px-2.5 py-2 border-b border-line'
const TD = 'px-2.5 py-2.5 border-b border-line align-top'
const TABLE_CARD = 'rounded-lg border border-cardline bg-panel overflow-x-auto'
const LINK = 'text-accent hover:underline'

const REACH_WORD: Record<DomainReach, string> = {
  full: 'fully assessed',
  partial: 'partly assessed',
  config_only: 'configuration only',
  none: 'not covered',
}

export function stateChip(d: SecurityDomain): { cls: string; text: string } {
  if (d.state === 'not_assessed') return { cls: 'csf-state-not_assessed', text: 'not assessed' }
  if (d.state === 'not_supplied') return { cls: 'csf-state-not_assessed', text: 'export not supplied' }
  if (d.state === 'clear') return { cls: 'csf-state-clear', text: 'no findings' }
  return { cls: 'csf-state-assessed', text: 'findings' }
}

export function Domains() {
  useTitle('Security Domains')
  const [view, setView] = useState<DomainsView | null>(null)
  const [failure, setFailure] = useState<string | null>(null)

  useEffect(() => {
    let live = true
    fetchDomains()
      .then((v) => { if (live) setView(v) })
      .catch((e: unknown) => {
        if (!live) return
        const status = e instanceof ApiError ? e.status : 0
        setFailure(`The domain view could not be loaded${status ? ` (HTTP ${status})` : ''}.`)
      })
    return () => { live = false }
  }, [])

  return (
    <>
      <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2 mb-1">
        <LayoutGrid size={22} className="text-accent shrink-0" />
        Security Domains
      </h1>
      <p className="text-ink2 mb-5 max-w-[80ch]">
        Your open findings in the twelve domains this market talks in. Each tile
        says two things that are easy to confuse and are not the same:{' '}
        <strong>what this product can see</strong> in that domain at all, and{' '}
        <strong>what this scan found</strong>.
      </p>

      {failure && <div className="banner banner-bad" role="alert">{failure}</div>}
      {!failure && view === null && <p className="text-[13px] text-ink3">Loading…</p>}
      {view !== null && <Body view={view} />}
    </>
  )
}

function Body({ view }: { view: DomainsView }) {
  const t = view.totals
  const notCovered = view.domains.filter((d) => d.reach === 'none')
  const configOnly = view.domains.filter((d) => d.reach === 'config_only')

  return (
    <>
      {/* Expectations are set BEFORE the tiles, because a reader forms them from
          the first grid they see and a correction underneath arrives too late. */}
      <div className="banner banner-info">
        This is a <strong>point-in-time configuration assessment</strong>. It reads
        what your systems are set to, not what they are doing.{' '}
        {configOnly.length > 0 && (
          <>
            {configOnly.length} of these domains are runtime activities, and what
            we contribute there is checking whether the configuration behind them
            is sound — worth having, and not the same as doing them.{' '}
          </>
        )}
        {notCovered.length > 0 && (
          <>
            {notCovered.length} we do not cover at all, and{' '}
            {notCovered.length === 1 ? 'it is' : 'they are'} marked as such rather
            than shown with a zero.
          </>
        )}
      </div>

      <div className={G3}>
        {view.domains.map((d) => <Tile key={d.id} d={d} />)}
      </div>

      {view.unplaced.total > 0 && (
        <>
          <h2 className={H2}>Findings these twelve domains have no word for</h2>
          <div className={TABLE_CARD}>
            <table className="w-full border-collapse">
              <thead>
                <tr>
                  <th className={TH}>Category</th>
                  <th className={`${TH} text-right`}>Findings</th>
                  <th className={TH}>Why it sits outside</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(view.unplaced.counts).map(([name, n]) => (
                  <tr key={name} className="hover:bg-panel2">
                    <td className={TD}>
                      <Link className={LINK}
                            to={`/findings?category=${encodeURIComponent(name)}`}>
                        {name}
                      </Link>
                    </td>
                    <td className={`${TD} text-right font-mono`}>{n}</td>
                    <td className={`${TD} text-[12px] text-ink2`}>
                      {view.unplaced.reasons[name] ?? '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="text-[12px] text-ink3 px-3.5 py-2.5 m-0">
              {view.unplaced.note}
            </p>
          </div>
        </>
      )}

      <p className="text-[12px] text-ink3 mt-6 max-w-[84ch]">
        {t.placed} of {t.findings} findings placed across {t.assessable} assessable
        domains. Each finding is counted <strong>once</strong> — no finding appears
        in two domains, so the tiles add up to the corpus rather than exceeding it.
        There is no score, no percentage and no maturity rating here, and there will
        not be one: we see your findings, not your control environment.
      </p>
    </>
  )
}

function Tile({ d }: { d: SecurityDomain }) {
  const chip = stateChip(d)
  const crit = d.counts.CRITICAL ?? 0
  const high = d.counts.HIGH ?? 0
  const covered = d.reach !== 'none'

  const inner = (
    <>
      <div className="flex items-start justify-between gap-2 mb-1">
        <span className="text-[13px] font-semibold text-ink leading-snug">
          {d.label}
        </span>
        <span className={`csf-state ${chip.cls} shrink-0`}>{chip.text}</span>
      </div>
      <div className="dom-reach mb-2">{REACH_WORD[d.reach]}</div>

      {covered ? (
        <>
          <div className="flex items-baseline gap-2">
            <span className={`${KPI} text-ink`}>{d.total}</span>
            <span className="text-[12px] text-ink2">
              open finding{d.total === 1 ? '' : 's'}
            </span>
          </div>
          <div className="flex flex-wrap gap-1.5 mt-2">
            {crit > 0 && <span className="pill sev-CRITICAL">{crit} critical</span>}
            {high > 0 && <span className="pill sev-HIGH">{high} high</span>}
          </div>
        </>
      ) : (
        <div className={`${KPI} text-ink3`}>&mdash;</div>
      )}

      {d.scope && <p className="dom-scope mt-2.5 m-0">{d.scope}</p>}
      {!d.scope && d.blurb && <p className="dom-scope mt-2.5 m-0">{d.blurb}</p>}
    </>
  )

  // A domain we do not cover is not a link: there is nothing behind it, and a
  // dead-end click reads as a broken screen rather than an honest boundary.
  if (!covered) {
    return <div className={`${CARD} dom-rail dom-rail-${d.reach}`}>{inner}</div>
  }
  return (
    <Link to={`/domains/${d.id}`}
          className={`${CARD} dom-rail dom-rail-${d.reach} block no-underline hover:bg-panel2`}>
      {inner}
    </Link>
  )
}
