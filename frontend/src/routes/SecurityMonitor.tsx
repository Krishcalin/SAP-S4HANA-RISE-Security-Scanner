/*
 * Security Monitor — the estate's posture on one screen.
 *
 * WHAT IT IS, AND WHOSE SHAPE IT BORROWS. The market's "security & compliance
 * monitors" present posture as a category strip with a per-check card under each.
 * This is that shape, over MonitorRisk's twelve security domains — so a reader
 * holding a competitor's screenshot finds the same furniture — with three things
 * those monitors do not have:
 *
 *   1. AN EMPTY TAB IS FOUR DIFFERENT THINGS, and only one is good news. The
 *      state carried from domains.roll_up (assessed / clear / not_supplied /
 *      not_assessed) decides how an empty domain reads; a strip that draws every
 *      empty cell the same way turns "we never looked" into a green tick.
 *   2. EACH CHECK SAYS WHO FIXES IT. Under RISE a customer can see a bad
 *      parameter and not be allowed to change it, so every card carries the
 *      owner badge — yours, or a SAP service request.
 *   3. A POSTURE BAND WITH ITS BASIS, and the annualised-loss headline beside it,
 *      given equal billing — a severity-weighted density over the checks that
 *      ran (never a compliance %), and the money a settings monitor cannot price.
 *
 * It reconciles with /domains by construction: the cards in a tab are grouped by
 * the same function domains.roll_up counts by, so their totals sum to the tab's.
 */
import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router'
import { Gauge } from 'lucide-react'

import { ApiError, securityMonitor as fetchMonitor } from '../api/client'
import type {
  RemediationOwner, SecurityMonitorCheck, SecurityMonitorDomain, SecurityMonitorView,
} from '../api/types'
import { useTitle } from '../lib/title'
import { CARD_TITLE, KPI, KPI_NOTE } from '../lib/ui'
import { MeasuredWhen } from '../components/MeasuredWhen'
import { stateChip } from './Domains'

const CARD = 'rounded-lg border border-cardline bg-panel p-4'
const LINK = 'text-accent hover:underline'
const SEV = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const

/** Severity → the CSS token for the proportion bar. Inline vars rather than
 *  `bg-{sev}` utilities, which Tailwind cannot generate from a built-up name. */
const SEV_VAR: Record<string, string> = {
  CRITICAL: 'var(--crit)', HIGH: 'var(--high)', MEDIUM: 'var(--med)',
  LOW: 'var(--low)', INFO: 'var(--ink-dim)',
}
/** Band → a LITERAL text class, so Tailwind sees each name and emits it. Low is
 *  green: it is the good band, not a quiet red. */
const BAND_CLS: Record<string, string> = {
  Critical: 'text-crit', High: 'text-high', Medium: 'text-med', Low: 'text-ok',
}
/** Worst severity → a LITERAL dot class for the tab strip. */
const DOT_CLS: Record<string, string> = {
  CRITICAL: 'bg-crit', HIGH: 'bg-high', MEDIUM: 'bg-med', LOW: 'bg-low', INFO: 'bg-ink2',
}
const OWNER_LABEL: Record<RemediationOwner, string> = {
  customer_fixable: 'Yours to fix',
  ticket_to_sap: 'SAP service request',
  provider_owned: 'SAP-operated',
  not_assessable: 'Not assessable',
}
const REACH_WORD: Record<string, string> = {
  full: 'fully assessed', partial: 'partly assessed',
  config_only: 'configuration only', none: 'not covered by this product',
}

/** What an empty tab means. The state decides, never the emptiness of the list. */
function emptyWord(d: SecurityMonitorDomain): string {
  if (d.reach === 'none') {
    return 'This product does not assess this domain in any run, so nothing here '
      + 'is a statement about your estate — it is a boundary, not a result.'
  }
  if (d.state === 'clear') return 'Assessed and came back with no findings. That is an observation that we looked, not a certification that the domain is secure.'
  if (d.state === 'not_supplied') return 'Nothing is listed because nothing was assessed — the export this domain reads was not supplied. An empty tab here is a blind spot, not a clean result.'
  if (d.state === 'not_assessed') return 'Not assessed in this run.'
  return 'Nothing to show.'
}

function money(n: number | null, currency: string): string {
  if (n === null || Number.isNaN(n)) return '—'
  try {
    return new Intl.NumberFormat(undefined, {
      style: 'currency', currency, maximumFractionDigits: n >= 1000 ? 1 : 0,
      notation: 'compact',
    }).format(n)
  } catch {
    return `${currency} ${Math.round(n).toLocaleString()}`
  }
}

function worstOf(counts: Record<string, number>): string | null {
  for (const s of SEV) if ((counts[s] ?? 0) > 0) return s
  return null
}

/** The severity spread of a check or a domain, as a proportion bar. */
function SevBar({ counts }: { counts: Record<string, number> }) {
  const total = SEV.reduce((n, s) => n + (counts[s] ?? 0), 0)
  if (!total) return null
  return (
    <div className="flex h-1.5 rounded-full overflow-hidden bg-panel2 gap-px"
         role="img" aria-label={SEV.filter((s) => counts[s]).map((s) => `${counts[s]} ${s.toLowerCase()}`).join(', ')}>
      {SEV.map((s) => (counts[s] ?? 0) > 0 ? (
        <span key={s} style={{ flexGrow: counts[s], background: SEV_VAR[s] }} />
      ) : null)}
    </div>
  )
}

function CheckCard({ c }: { c: SecurityMonitorCheck }) {
  return (
    <Link to={`/findings?check=${encodeURIComponent(c.check_id)}`}
          className={`${CARD} block no-underline hover:bg-panel2 transition-colors flex flex-col gap-2`}>
      <div className="font-mono text-[11px] text-ink3">{c.check_id}</div>
      <div className="text-[13.5px] font-semibold text-ink leading-snug">{c.title}</div>
      <SevBar counts={c.counts} />
      <div className="flex items-center flex-wrap gap-2 mt-0.5">
        {c.worst && (
          <span className={`pill sev-${c.worst}`}>
            {c.total} finding{c.total === 1 ? '' : 's'}
          </span>
        )}
        <span className={`own own-${c.owner}`}>{OWNER_LABEL[c.owner]}</span>
      </div>
    </Link>
  )
}

function DomainPanel({ d }: { d: SecurityMonitorDomain }) {
  const chip = stateChip(d)
  return (
    <section>
      <div className="flex items-center justify-between gap-3 flex-wrap mb-1">
        <h2 className="text-[15px] font-semibold text-ink">
          <Link className="hover:underline" to={`/domains/${d.id}`}>{d.label}</Link>
        </h2>
        <span className={`csf-state ${chip.cls}`}>{chip.text}</span>
      </div>
      <p className="dom-reach mb-1">{REACH_WORD[d.reach] ?? d.reach}</p>
      {d.scope && <p className="dom-scope mb-3 max-w-[80ch]">{d.scope}</p>}

      {d.checks.length === 0 ? (
        <div className={`banner ${d.state === 'clear' ? 'banner-ok' : 'banner-info'}`}>
          {emptyWord(d)}
        </div>
      ) : (
        <>
          <div className="grid gap-3 [grid-template-columns:repeat(auto-fill,minmax(300px,1fr))]">
            {d.checks.map((c) => <CheckCard key={c.check_id} c={c} />)}
          </div>
          <p className="text-[12px] text-ink3 mt-3">
            {d.checks.length} failing check{d.checks.length === 1 ? '' : 's'} ·{' '}
            {d.total} finding{d.total === 1 ? '' : 's'} in this domain.
          </p>
        </>
      )}
    </section>
  )
}

/** One tab: the domain label, and a marker that is the worst-severity dot when it
 *  has findings, or the state word when it does not — so the strip itself carries
 *  the four-state honesty before a tab is ever opened. */
function Tab({ d, active, onClick }: {
  d: SecurityMonitorDomain; active: boolean; onClick: () => void
}) {
  const worst = worstOf(d.counts)
  return (
    <button role="tab" aria-selected={active} onClick={onClick}
            className={`flex items-center gap-2 whitespace-nowrap px-3.5 py-2.5 text-[13px] font-semibold
              border-b-2 ${active ? 'border-accent text-accent' : 'border-transparent text-ink3 hover:text-ink2'}`}>
      {d.total > 0
        ? <span className={`inline-block w-2 h-2 rounded-full ${worst ? DOT_CLS[worst] : 'bg-ink3'}`} />
        : <span className={`inline-block w-2 h-2 rounded-full border border-dashed
            ${d.state === 'clear' ? 'border-ok' : 'border-ink3'}`} />}
      {d.label}
      {d.total > 0 && (
        <span className="font-mono text-[11px] text-ink3 tabular-nums">{d.total}</span>
      )}
    </button>
  )
}

function Headline({ view }: { view: SecurityMonitorView }) {
  const t = view.totals
  const p = view.posture
  const r = view.risk
  return (
    <>
      {/* The two headline figures, equal billing: a severity-weighted band and the
          money. A settings monitor produces neither. */}
      <div className="grid gap-3.5 sm:grid-cols-2 mb-3.5">
        <div className={CARD}>
          <div className={CARD_TITLE}>Posture</div>
          {p ? (
            <>
              <div className="flex items-baseline gap-2">
                <span className={`${KPI} ${BAND_CLS[p.band] ?? 'text-ink'}`}>{p.band}</span>
                <span className="text-[13px] text-ink2 tabular-nums">score {p.score}/100</span>
              </div>
              <p className={KPI_NOTE}>{p.basis} {p.anchor}</p>
            </>
          ) : (
            <>
              <div className={`${KPI} text-ink3`}>—</div>
              <p className={KPI_NOTE}>
                No posture band: nothing supplied a manifest to divide by, so there
                is no honest denominator. The severity counts below stand on their own.
              </p>
            </>
          )}
        </div>

        <div className={CARD}>
          <div className={CARD_TITLE}>Annualised loss exposure</div>
          {r ? (
            <>
              <div className="flex items-baseline gap-2">
                <span className={`${KPI} text-ink`}>{money(r.ale_p90, r.currency)}</span>
                <span className="text-[13px] text-ink2">P90 · FAIR</span>
              </div>
              <p className={KPI_NOTE}>
                90th-percentile annual loss across the modelled scenarios
                {r.ale_mean !== null && <> · mean {money(r.ale_mean, r.currency)}</>}.
                {!r.priced && (
                  <> {' '}<span className="text-high">Illustrative model — not this
                  organisation's own figures.</span>{' '}
                  <Link className={LINK} to="/crq">Enter your figures →</Link></>
                )}
              </p>
            </>
          ) : (
            <>
              <div className={`${KPI} text-ink3`}>Not quantified</div>
              <p className={KPI_NOTE}>
                No priced scenario yet.{' '}
                <Link className={LINK} to="/crq">Quantify risk →</Link>
              </p>
            </>
          )}
        </div>
      </div>

      {/* The four counts a reader scans first — and `not assessed` is its own tile,
          never folded into `clear`. */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3.5 mb-6">
        <Stat n={t.findings} label="Open findings" tone="text-ink" />
        <Stat n={t.gaps} label="Failing checks" tone="text-crit" />
        <Stat n={t.clear} label="Domains clear" tone="text-ok" />
        <Stat n={t.not_assessed} label="Domains not assessed" tone="text-ink3" />
      </div>
    </>
  )
}

function Stat({ n, label, tone }: { n: number; label: string; tone: string }) {
  return (
    <div className={CARD}>
      <div className={`${KPI} ${tone} tabular-nums`}>{n}</div>
      <div className={KPI_NOTE}>{label}</div>
    </div>
  )
}

export function SecurityMonitor() {
  useTitle('Security Monitor')
  const [view, setView] = useState<SecurityMonitorView | null>(null)
  const [failure, setFailure] = useState<string | null>(null)
  const [active, setActive] = useState<string | null>(null)

  useEffect(() => {
    let live = true
    fetchMonitor()
      .then((data) => {
        if (!live) return
        setView(data)
        // Open on the first domain that actually has findings, so the screen lands
        // on something to read rather than on an alphabetically-first empty tab.
        const firstWithFindings = data.domains.find((d) => d.total > 0)
        setActive((firstWithFindings ?? data.domains[0])?.id ?? null)
      })
      .catch((problem) => {
        if (!live) return
        setFailure(problem instanceof ApiError ? problem.message
          : 'Could not load the security monitor.')
      })
    return () => { live = false }
  }, [])

  const activeDomain = useMemo(
    () => view?.domains.find((d) => d.id === active) ?? null,
    [view, active])

  if (failure) return <p className="text-crit">{failure}</p>
  if (!view) return <p className="text-ink2">Loading…</p>

  return (
    <>
      <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2 mb-1">
        <Gauge size={22} className="text-accent shrink-0" />
        Security Monitor
      </h1>
      <MeasuredWhen measured={view.measured} subject="posture" />
      <p className="text-ink2 mb-5 max-w-[80ch]">
        Your posture across the twelve security domains, each with the checks that
        failed inside it. The band and the loss figure are measured over what was
        actually assessed; an empty tab says which of four things it means, and
        every check says whether it is yours to fix or a SAP service request.
      </p>

      <Headline view={view} />

      <div className="flex gap-1 overflow-x-auto border-b border-line mb-4"
           role="tablist" aria-label="Security domains"
           style={{ scrollbarWidth: 'none' }}>
        {view.domains.map((d) => (
          <Tab key={d.id} d={d} active={d.id === active} onClick={() => setActive(d.id)} />
        ))}
      </div>

      {activeDomain && <DomainPanel d={activeDomain} />}
    </>
  )
}
