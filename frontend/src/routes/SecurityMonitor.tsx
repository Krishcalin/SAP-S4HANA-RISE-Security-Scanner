/*
 * Security Monitor — the estate's posture on one screen.
 *
 * WHAT IT IS, AND WHOSE SHAPE IT BORROWS. The market's "security & compliance
 * monitors" present posture as a system header, a summary band and a category
 * strip with per-check cards under it. This is that shape, over MonitorRisk's
 * twelve security domains, with three things those monitors do not have:
 *
 *   1. AN EMPTY TAB IS FOUR DIFFERENT THINGS, and only one is good news. The
 *      state from domains.roll_up (assessed / clear / not_supplied /
 *      not_assessed) decides how an empty domain reads.
 *   2. EACH CHECK SAYS WHO FIXES IT — yours, or a SAP service request under RISE.
 *   3. A POSTURE BAND WITH ITS BASIS and the annualised-loss headline beside it,
 *      given equal billing.
 *
 * The furniture (.sm-* classes) lives in index.css and is built on the console's
 * own tokens, so it follows the OS theme with no toggle of its own. It reconciles
 * with /domains by construction — the cards in a tab are grouped by the same
 * function domains.roll_up counts by, so their totals sum to the tab's.
 */
import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router'
import { Gauge, CircleAlert, X } from 'lucide-react'

import {
  ApiError, checkDoc as fetchCheckDoc, securityMonitor as fetchMonitor,
} from '../api/client'
import type {
  CheckDoc, RemediationOwner, SecurityMonitorCheck, SecurityMonitorDomain,
  SecurityMonitorView,
} from '../api/types'
import { useTitle } from '../lib/title'

const SEV = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const
/** Severity → the lowercase token the .sm-*-{x} classes use. */
const LC: Record<string, string> = {
  CRITICAL: 'crit', HIGH: 'high', MEDIUM: 'med', LOW: 'low', INFO: 'na',
}
const SEV_LABEL: Record<string, string> = {
  CRITICAL: 'Critical', HIGH: 'High', MEDIUM: 'Medium', LOW: 'Low', INFO: 'Info',
}
const BAND_LC: Record<string, string> = {
  Critical: 'critical', High: 'high', Medium: 'medium', Low: 'low',
}
const OWNER: Record<RemediationOwner, { cls: string; short: string; long: string }> = {
  customer_fixable: { cls: 'sm-pill-yours', short: 'Yours', long: 'You — customer-fixable' },
  ticket_to_sap: { cls: 'sm-pill-sap', short: 'SAP request', long: 'SAP — service request (RISE)' },
  provider_owned: { cls: 'sm-pill-sap', short: 'SAP-operated', long: 'SAP-operated under RISE' },
  not_assessable: { cls: 'sm-pill-na', short: 'N/A', long: 'Not assessable' },
}
function money(n: number | null | undefined, currency: string): string {
  if (n === null || n === undefined || Number.isNaN(n)) return '—'
  try {
    return new Intl.NumberFormat(undefined, {
      style: 'currency', currency, maximumFractionDigits: n >= 1000 ? 1 : 0,
      notation: 'compact',
    }).format(n)
  } catch { return `${currency} ${Math.round(n).toLocaleString()}` }
}
function fmtDate(iso: string | null | undefined): string {
  if (!iso) return ''
  const d = new Date(iso)
  return Number.isNaN(+d) ? '' : d.toLocaleDateString(undefined,
    { day: '2-digit', month: 'short', year: 'numeric' })
}
function ago(days: number | undefined): string {
  if (days === undefined || days === null) return ''
  return days === 0 ? 'today' : days === 1 ? 'yesterday' : `${days} days ago`
}
function worstOf(counts: Record<string, number>): string | null {
  for (const s of SEV) if ((counts[s] ?? 0) > 0) return s
  return null
}

/** The severity spread of a check or a domain, as a proportion bar. */
function SevBar({ counts, faint }: { counts: Record<string, number>; faint?: boolean }) {
  const total = SEV.reduce((n, s) => n + (counts[s] ?? 0), 0)
  if (!total) {
    return (
      <div className="sm-sevbar">
        <span className="sm-sfill-na" style={{ flexGrow: 1, opacity: faint ? 0.35 : 1 }} />
      </div>
    )
  }
  return (
    <div className="sm-sevbar"
         role="img" aria-label={SEV.filter((s) => counts[s]).map((s) => `${counts[s]} ${SEV_LABEL[s].toLowerCase()}`).join(', ')}>
      {SEV.map((s) => (counts[s] ?? 0) > 0
        ? <span key={s} className={`sm-sfill-${LC[s]}`} style={{ flexGrow: counts[s] }} />
        : null)}
    </div>
  )
}

/** The domain's risk level — worst severity present, or its state when empty. */
function levelOf(d: SecurityMonitorDomain): { cls: string; text: string } {
  if (d.reach === 'none' || d.state === 'not_assessed' || d.state === 'not_supplied') {
    return { cls: 'sm-lvl-na', text: 'N/A' }
  }
  const w = worstOf(d.counts)
  if (w === 'CRITICAL') return { cls: 'sm-lvl-critical', text: 'Critical' }
  if (w === 'HIGH') return { cls: 'sm-lvl-high', text: 'High' }
  if (w === 'MEDIUM') return { cls: 'sm-lvl-medium', text: 'Medium' }
  if (w === 'LOW') return { cls: 'sm-lvl-low', text: 'Low' }
  return { cls: 'sm-lvl-low', text: 'Clear' }
}

function emptyWord(d: SecurityMonitorDomain): string {
  if (d.reach === 'none') {
    return 'This product does not assess this domain in any run, so nothing here '
      + 'is a statement about your estate — it is a boundary, not a result.'
  }
  if (d.state === 'clear') return 'Assessed and came back with no findings — an observation that we looked, not a certification that the domain is secure.'
  if (d.state === 'not_supplied') return 'Nothing is listed because nothing was assessed — the export this domain reads was not supplied. An empty tab here is a blind spot, not a clean result.'
  if (d.state === 'not_assessed') return 'Not assessed in this run.'
  return 'Nothing to show.'
}

// ── the detail drawer ─────────────────────────────────────────────────────────
function Drawer({ check, domain, measured, onClose }: {
  check: SecurityMonitorCheck
  domain: SecurityMonitorDomain
  measured: string
  onClose: () => void
}) {
  const [doc, setDoc] = useState<CheckDoc | null>(null)
  const [docState, setDocState] = useState<'loading' | 'done' | 'error'>('loading')
  const w = check.worst ? LC[check.worst] : 'na'
  const owner = OWNER[check.owner]

  useEffect(() => {
    let live = true
    setDocState('loading'); setDoc(null)
    fetchCheckDoc(check.check_id)
      .then((d) => { if (live) { setDoc(d); setDocState('done') } })
      .catch(() => { if (live) setDocState('error') })
    return () => { live = false }
  }, [check.check_id])

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onClose])

  return (
    <>
      <div className="sm-scrim sm-open" onClick={onClose} />
      <aside className="sm-drawer sm-open" role="dialog" aria-label={check.check_id}>
        <div className="sm-dhead">
          <span className={`sm-swatch sm-sfill-${w}`} style={{ width: 12, height: 12, borderRadius: 4, marginTop: 5 }} />
          <div style={{ minWidth: 0 }}>
            <div className="sm-cid">{check.check_id} · {domain.label}</div>
            <div style={{ fontSize: 16, fontWeight: 700, lineHeight: 1.3, marginTop: 2 }}>{check.title}</div>
          </div>
          <button className="sm-dclose" aria-label="Close" onClick={onClose}><X size={16} /></button>
        </div>
        <div className="sm-dbody">
          <div className="sm-dsec">
            <div className="sm-kv"><span className="sm-k">Status</span>
              <span className={`sm-v sm-c-${w}`}>{check.worst ? `${SEV_LABEL[check.worst]} gap` : 'Gap'}</span></div>
            <div className="sm-kv"><span className="sm-k">Who fixes it</span><span className="sm-v">{owner.long}</span></div>
            <div className="sm-kv"><span className="sm-k">Last measured</span><span className="sm-v">{measured || '—'}</span></div>
            <div className="sm-kv"><span className="sm-k">Findings</span><span className="sm-v">{check.total}</span></div>
          </div>

          <div className="sm-dsec">
            <h4>Findings by severity</h4>
            {SEV.filter((s) => check.counts[s]).map((s) => (
              <div className="sm-kv" key={s}>
                <span className="sm-k">{SEV_LABEL[s]}</span>
                <span className={`sm-v sm-c-${LC[s]}`}>{check.counts[s]}</span>
              </div>
            ))}
          </div>

          <div className="sm-dsec">
            <h4>Risk</h4>
            {docState === 'loading' && <p>Loading…</p>}
            {docState === 'error' && <p>Could not load the check description.</p>}
            {docState === 'done' && <p>{doc?.risk || 'No authored risk narrative for this check.'}</p>}
          </div>
          <div className="sm-dsec">
            <h4>Remediation</h4>
            {docState === 'loading' && <p>Loading…</p>}
            {docState === 'done' && <p>{doc?.mitigation || 'No authored remediation for this check.'}</p>}
          </div>

          <div className="sm-dsec">
            <Link className="sm-chip" style={{ justifyContent: 'center', width: '100%' }}
                  to={`/findings?check=${encodeURIComponent(check.check_id)}`}>
              Open {check.total} finding{check.total === 1 ? '' : 's'} in the queue →
            </Link>
          </div>
        </div>
      </aside>
    </>
  )
}

// ── the summary band ──────────────────────────────────────────────────────────
function Summary({ view }: { view: SecurityMonitorView }) {
  const t = view.totals
  const p = view.posture
  const r = view.risk
  const assessed = p?.assessed ?? null
  const clearChecks = assessed === null ? null : Math.max(0, assessed - t.gaps)
  const notAssessedChecks = assessed === null ? null : Math.max(0, t.checks_total - assessed)
  const bandCls = p ? (BAND_LC[p.band] ?? 'na') : 'na'

  const tile = (n: number | string | null, label: string, cls = '') => (
    <div className="sm-tile">
      <div className={`sm-n ${cls}`}>{n === null ? '—' : n}</div>
      <div className="sm-l">{label}</div>
    </div>
  )

  return (
    <section className="sm-summary">
      <div className="sm-card sm-pad sm-sev">
        <div className="sm-ptitle" style={{ marginBottom: 12 }}>Posture — estate</div>
        <div className="sm-tiles">
          {tile(assessed, 'Checks run')}
          {tile(t.gaps, 'Failing checks', 'sm-c-crit')}
          {tile(clearChecks, 'Checks clear', 'sm-c-ok')}
          {tile(notAssessedChecks, 'Not assessed', 'sm-c-na')}
          <div className="sm-tile sm-full">
            <div className="sm-l" style={{ fontSize: 12 }}>
              {t.findings} finding{t.findings === 1 ? '' : 's'} across {t.gaps} failing check{t.gaps === 1 ? '' : 's'}
            </div>
            <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap' }}>
              {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map((s) => (
                <span key={s} className={`sm-l sm-c-${LC[s]}`} style={{ fontSize: 12.5, fontWeight: 700 }}>
                  {t.counts[s] ?? 0} {SEV_LABEL[s]}
                </span>
              ))}
            </div>
          </div>
        </div>

        {/* severity spread of the open findings, with a clear segment for context */}
        <div className="sm-sevbar" style={{ marginTop: 13 }} title="Open findings by severity">
          {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map((s) => (t.counts[s] ?? 0) > 0
            ? <span key={s} className={`sm-sfill-${LC[s]}`} style={{ flexGrow: t.counts[s] }} /> : null)}
          {clearChecks ? <span className="sm-sfill-ok" style={{ flexGrow: clearChecks }} /> : null}
          {t.findings === 0 && !clearChecks ? <span className="sm-sfill-na" style={{ flexGrow: 1, opacity: 0.35 }} /> : null}
        </div>
        <div className="sm-legend">
          <span><i className="sm-swatch sm-sfill-crit" />Critical</span>
          <span><i className="sm-swatch sm-sfill-high" />High</span>
          <span><i className="sm-swatch sm-sfill-med" />Medium</span>
          <span><i className="sm-swatch sm-sfill-low" />Low</span>
          <span><i className="sm-swatch sm-sfill-ok" />Clear</span>
          <span><i className="sm-swatch sm-sfill-na" />Not assessed</span>
        </div>

        <div className="sm-rate">
          <span className={`sm-band sm-band-${bandCls}`}>{p ? `${p.band} risk` : 'Not scored'}</span>
          <span className="sm-note">
            {p
              ? <>{p.basis} {p.anchor} <b>Clear</b> means a check looked and found nothing; it is not a certification.</>
              : 'No manifest supplied a denominator, so there is no honest density to score — the counts stand on their own.'}
          </span>
          <div className="sm-money">
            {r
              ? <>
                  <div className="sm-n">{money(r.ale_p90, r.currency)}</div>
                  <div className="sm-l">annualised loss · FAIR P90{!r.priced ? ' · illustrative' : ''}</div>
                </>
              : <>
                  <div className="sm-n" style={{ fontSize: 15 }}>Not quantified</div>
                  <div className="sm-l"><Link className="sm-chip" style={{ padding: '1px 8px' }} to="/crq">Quantify →</Link></div>
                </>}
          </div>
        </div>
      </div>

      <div className="sm-card sm-pad sm-sev">
        <div className="sm-ptitle" style={{ marginBottom: 6 }}>Security level by domain</div>
        {view.domains.map((d) => {
          const lvl = levelOf(d)
          return (
            <Link key={d.id} className="sm-domrow" to={`/domains/${d.id}`}>
              <span className="sm-dn">{d.label}</span>
              <SevBar counts={d.counts} faint />
              <span className={`sm-lvl ${lvl.cls}`}>{lvl.text}</span>
              <span className="sm-domcount">{d.total || '—'}</span>
            </Link>
          )
        })}
      </div>
    </section>
  )
}

export function SecurityMonitor() {
  useTitle('Security Monitor')
  const [view, setView] = useState<SecurityMonitorView | null>(null)
  const [failure, setFailure] = useState<string | null>(null)
  const [active, setActive] = useState<string | null>(null)
  const [sev, setSev] = useState<string | null>(null)
  const [own, setOwn] = useState<string | null>(null)
  const [drawer, setDrawer] = useState<{ check: SecurityMonitorCheck; domain: SecurityMonitorDomain } | null>(null)

  useEffect(() => {
    let live = true
    fetchMonitor()
      .then((data) => {
        if (!live) return
        setView(data)
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
    () => view?.domains.find((d) => d.id === active) ?? null, [view, active])

  const shown = useMemo(() => {
    if (!activeDomain) return []
    return activeDomain.checks.filter((c) => {
      if (sev && !(c.counts[sev])) return false
      if (own && c.owner !== own) return false
      return true
    })
  }, [activeDomain, sev, own])

  if (failure) return <p className="text-crit">{failure}</p>
  if (!view) return <p className="text-ink2">Loading…</p>

  const ctx = view.context
  const measuredDate = fmtDate(view.measured?.newest)
  const chip = (label: string, key: 'sev' | 'own', value: string, swatch?: string) => {
    const on = key === 'sev' ? sev === value : own === value
    const set = key === 'sev' ? setSev : setOwn
    return (
      <button className="sm-chip" aria-pressed={on}
              onClick={() => set(on ? null : value)}>
        {swatch && <i className={`sm-swatch sm-sfill-${swatch}`} />}{label}
      </button>
    )
  }

  return (
    <>
      <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2 mb-2">
        <Gauge size={22} className="text-accent shrink-0" />
        Security Monitor
      </h1>

      <div className="sm-ctx">
        <span className="sm-syspick">
          <span className="sm-dot" />
          {ctx.systems ? `${ctx.systems} system${ctx.systems === 1 ? '' : 's'} in scope` : 'Estate'}
        </span>
        <span className="sm-meta">
          {ctx.standard && <><b>{ctx.standard}</b><span className="sm-sep">•</span></>}
          {measuredDate && <><span>measured <b>{measuredDate}</b>{view.measured && ` (${ago(view.measured.oldest_days)})`}</span><span className="sm-sep">•</span></>}
          {ctx.sources_known
            ? <span><b>{ctx.sources_supplied ?? 0}</b> of {ctx.sources_known} export sources supplied</span>
            : <span>offline / retrospective assessment</span>}
        </span>
      </div>

      <Summary view={view} />

      <div className="sm-tabs" role="tablist" aria-label="Security domains">
        {view.domains.map((d) => {
          const gaps = d.checks.length
          return (
            <button key={d.id} role="tab" aria-selected={d.id === active}
                    className="sm-tab" onClick={() => { setActive(d.id); setSev(null); setOwn(null) }}>
              {d.label}
              {gaps > 0 && <span className="sm-cnt">{gaps}</span>}
            </button>
          )
        })}
      </div>

      {activeDomain && (
        <>
          <div className="sm-filter">
            <span className="sm-flab">Severity</span>
            {chip('Critical', 'sev', 'CRITICAL', 'crit')}
            {chip('High', 'sev', 'HIGH', 'high')}
            {chip('Medium', 'sev', 'MEDIUM', 'med')}
            <span className="sm-flab" style={{ marginLeft: 8 }}>Owner</span>
            {chip('Yours to fix', 'own', 'customer_fixable')}
            {chip('SAP service request', 'own', 'ticket_to_sap')}
          </div>

          {activeDomain.checks.length === 0 ? (
            <div className={`banner ${activeDomain.state === 'clear' ? 'banner-ok' : 'banner-info'}`}>
              {emptyWord(activeDomain)}
            </div>
          ) : (
            <>
              <div className="sm-grid">
                {shown.map((c) => {
                  const w = c.worst ? LC[c.worst] : 'na'
                  const o = OWNER[c.owner]
                  return (
                    <button key={c.check_id} className={`sm-chk sm-b-${w}`}
                            aria-haspopup="dialog"
                            onClick={() => setDrawer({ check: c, domain: activeDomain })}>
                      <div className="sm-cid">{c.check_id}</div>
                      <div className="sm-ct">{c.title}</div>
                      <SevBar counts={c.counts} />
                      <div className="sm-foot">
                        <span className={`sm-stat sm-c-${w}`}><CircleAlert size={16} />{c.total}</span>
                        <span className={`sm-pill ${o.cls}`}>{o.short}</span>
                        {measuredDate && <span className="sm-run">{measuredDate}</span>}
                      </div>
                    </button>
                  )
                })}
              </div>
              <p className="sm-domnote">
                {activeDomain.checks.length} failing check{activeDomain.checks.length === 1 ? '' : 's'} ·{' '}
                {activeDomain.total} finding{activeDomain.total === 1 ? '' : 's'} in this domain
                {shown.length !== activeDomain.checks.length && ` · ${shown.length} match the filter`}.
                {' '}An empty or clean check is not listed here — the strip above and the{' '}
                <Link className="text-accent hover:underline" to={`/domains/${activeDomain.id}`}>domain page</Link>{' '}
                carry what was assessed clean versus not assessed at all.
              </p>
            </>
          )}
        </>
      )}

      {drawer && (
        <Drawer check={drawer.check} domain={drawer.domain} measured={measuredDate}
                onClose={() => setDrawer(null)} />
      )}
    </>
  )
}
