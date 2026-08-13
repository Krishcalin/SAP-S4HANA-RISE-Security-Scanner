/*
 * Copyright (c) 2026 Krishnendu De. All Rights Reserved.
 *
 * Author : Krishnendu De
 * Coding Assistance : Claude Code
 * Code Security Assistance : Code QL
 */

import { useEffect, useState } from 'react'
import { Link } from 'react-router'
import { ApiError, csf, dashboard } from '../api/client'
import type {
  CsfView, Dashboard as DashboardData, RemediationOwner, ScanRun, Severity,
} from '../api/types'
import { useTitle } from '../lib/title'
// The ONE transcription of server/app.py `_money`, exported from the screen the
// currency figure belongs to. A second copy here read identically today and
// would drift from it and from the server on the first rounding change — which
// is how a board pack and the dashboard beside it start disagreeing.
import { isPriced } from '../lib/pricing'
import { money } from './Risk'

/**
 * The landing screen — ported from server/templates/dashboard.html.
 *
 * IT LEADS WITH THREE BANNERS RATHER THAN THE COUNTS. An expired risk acceptance
 * is itself an audit finding, a regression is a process failure rather than a
 * backlog item, and a finding matched across runs by display text has a history
 * that would reset if the check were reworded. All three are things a reader has
 * to be TOLD; none of them survives being a number in a grid, and putting them
 * behind a filter means nobody ever applies it. The wording is carried over from
 * the template verbatim — it is the product's voice, and a migration that
 * paraphrases it quietly makes the product worse.
 *
 * THE CURRENCY FIGURE SITS BESIDE THE FINDING COUNTS, not behind a flag: neither
 * incumbent produces one at all, so it is the most differentiated thing here.
 */
export function Dashboard() {
  useTitle('Dashboard')
  const [data, setData] = useState<DashboardData | null>(null)
  const [error, setError] = useState('')
  const [csfView, setCsfView] = useState<CsfView | null>(null)

  useEffect(() => {
    let cancelled = false
    dashboard()
      .then((d) => { if (!cancelled) setData(d) })
      .catch((e) => { if (!cancelled) setError(describe(e)) })
    return () => { cancelled = true }
  }, [])

  // A SEPARATE request, and a swallowed failure. The CSF strip is context for
  // the findings above it, not the reason anyone opens this screen; letting its
  // roll-up fail the whole dashboard would trade the four panels a reader came
  // for against a panel they did not. On failure the strip renders nothing,
  // which is honest — it never renders empty tiles, because six zeroes read as
  // "clean in every Function" rather than "this did not load".
  useEffect(() => {
    let cancelled = false
    csf()
      .then((v) => { if (!cancelled) setCsfView(v) })
      .catch(() => { /* strip stays hidden; see above */ })
    return () => { cancelled = true }
  }, [])

  if (error) return <div className="banner banner-bad" role="alert">{error}</div>
  if (!data) return <p className="text-ink3 text-[13px]">Loading…</p>

  const { summary, systems, recent_runs, crq, crq_scenarios } = data
  const reducible = num(crq?.detail?.['reducible_ale_p90'])

  return (
    <>
      {/* The brand, on the screen people land on. It is a band rather than a hero
          BECAUSE of the note above: the three banners below are the point of this
          screen, and a full-bleed lockup at this aspect (2.74:1) would be 400px
          tall and push every one of them under the fold. Height-capped in CSS, so
          a re-exported master cannot quietly turn a header into a splash page.
          alt="" — the <h1> immediately after it already names the screen, and the
          wordmark is decorative once the page has a heading. */}
      <div className="brand-band">
        <img src="/static/monitorrisk-logo.png" width={1100} height={401} alt="" />
      </div>

      <h1 className="text-[21px] font-semibold tracking-[-.01em] mb-1">Security posture</h1>
      <p className="text-ink2 mb-5">
        Open findings across {systems.length} system{systems.length === 1 ? '' : 's'}.
      </p>

      {summary.expired_acceptances > 0 && (
        <div className="banner banner-bad">
          <strong className="font-semibold">
            {summary.expired_acceptances} risk acceptance
            {summary.expired_acceptances === 1 ? '' : 's'} expired.
          </strong>{' '}
          The underlying defect is open again and the time-box has passed.{' '}
          <Link className="text-accent" to="/findings?state=accepted">Review</Link>
        </div>
      )}

      {summary.regressed > 0 && (
        <div className="banner banner-warn">
          <strong className="font-semibold">
            {summary.regressed} finding{summary.regressed === 1 ? '' : 's'} regressed
          </strong>{' '}
          — previously resolved, then seen again. A recurring defect is a process
          failure, not a one-off.
        </div>
      )}

      {summary.weak_identity > 0 && (
        <div className="banner banner-info">
          {summary.weak_identity} finding{summary.weak_identity === 1 ? '' : 's'} are
          matched across runs by display text rather than by structured object
          identity. They track correctly today, but their history would reset if the
          check&rsquo;s wording changed.
        </div>
      )}

      <div className={G4}>
        <div className={CARD}>
          <h3 className={CARD_TITLE}>Open findings</h3>
          <div className={KPI}>{summary.open_total}</div>
          <div className={KPI_NOTE}>excluding resolved and disputed</div>
        </div>
        <div className={CARD}>
          <h3 className={CARD_TITLE}>Critical</h3>
          <div className={`${KPI} text-crit`}>{summary.by_severity.CRITICAL ?? 0}</div>
          <div className={KPI_NOTE}>{summary.by_severity.HIGH ?? 0} high</div>
        </div>
        <div className={CARD}>
          <h3 className={CARD_TITLE}>Yours to fix</h3>
          <div className={`${KPI} text-ok`}>
            {summary.by_remediation_owner.customer_fixable ?? 0}
          </div>
          <div className={KPI_NOTE}>actionable without SAP</div>
        </div>
        <div className={CARD}>
          <h3 className={CARD_TITLE}>Raise with SAP</h3>
          <div className={`${KPI} text-high`}>
            {summary.by_remediation_owner.ticket_to_sap ?? 0}
          </div>
          <div className={KPI_NOTE}>
            {summary.by_state.submitted_to_provider ?? 0} already submitted
          </div>
        </div>
      </div>

      {/* isPriced GATES THIS, NOT JUST ale_p90 !== null.
          A figure exists on every stored row; whether it was the CUSTOMER'S is a
          different question, and the dashboard was answering the first while
          appearing to answer the second. Unpriced, the pair is absent rather
          than caveated — the same rule the reports obey, and a card nobody can
          screenshot is the only caveat that survives being screenshotted. */}
      {crq && crq.ale_p90 !== null && isPriced(crq) && (
        <div className={`${G2} mt-3.5`}>
          <div className={CARD}>
            <h3 className={CARD_TITLE}>Annualised loss exposure</h3>
            <div className="flex items-baseline gap-[18px] flex-wrap">
              <div className={KPI}>{money(crq.ale_p90)}</div>
              <div className="text-ink2 text-[12px]">
                90th percentile · median {money(crq.ale_p50)}<br />
                <span className="text-ok">{money(reducible)}</span> reducible by
                remediation
              </div>
            </div>
            <div className={KPI_NOTE}>
              Priced on all {crq.input_finding_count} findings — a display filter
              cannot move this number.{' '}
              {crq.unrouted_count > 0 && `${crq.unrouted_count} unattributed and disclosed. `}
              <Link className="text-accent" to="/risk">Breakdown →</Link>
            </div>
          </div>
          <div className={CARD}>
            <h3 className={CARD_TITLE}>Where the exposure sits</h3>
            <table className="w-full border-collapse">
              <tbody>
                {crq_scenarios.slice(0, 5).map((s) => (
                  <tr key={s.id} className="hover:bg-panel2">
                    <td className={`${TD} font-mono text-[12px] w-[104px]`}>
                      {s.scenario_id}
                    </td>
                    <td className={`${TD} text-[12px] text-ink2`}>
                      {str(s.detail?.['name']).slice(0, 42)}
                    </td>
                    <td className={`${TD} text-right font-mono`}>{money(s.ale_p90)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <div className={`${G2} mt-3.5`}>
        <div className={CARD}>
          <h3 className={CARD_TITLE}>By severity</h3>
          <table className="w-full border-collapse">
            <tbody>
              {SEVERITIES.map((sev) => {
                const n = summary.by_severity[sev] ?? 0
                if (!n) return null
                const pct = summary.open_total ? (100 * n) / summary.open_total : 0
                return (
                  <tr key={sev} className="hover:bg-panel2">
                    <td className={`${TD} w-[110px]`}>
                      <span className={`pill sev-${sev}`}>{sev}</span>
                    </td>
                    <td className={`${TD} text-right font-mono`}>{n}</td>
                    <td className={`${TD} w-[55%]`}>
                      <div className="mt-2 h-1.5 rounded-[3px] bg-panel2 overflow-hidden">
                        <i className="block h-full bg-accent" style={{ width: `${pct}%` }} />
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>

        <div className={CARD}>
          <h3 className={CARD_TITLE}>Remediation ownership</h3>
          {/* Four classes, because reporting an SAP-owned setting as a customer
              failure — or as "unknown" — is how a RISE report fills with
              unactionable noise. */}
          <table className="w-full border-collapse">
            <tbody>
              {OWNERS.map(([key, label]) => (
                <tr key={key} className="hover:bg-panel2">
                  <td className={TD}><span className={`own own-${key}`}>{label}</span></td>
                  <td className={`${TD} text-right font-mono`}>
                    {summary.by_remediation_owner[key] ?? 0}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* NIST CSF 2.0 — the signal that these findings sit inside a framework a
          reader already trusts. Six tiles, one per Function, each a link into
          /csf/<function>. It is guarded on `csfView` for the reason the CRQ pair
          above is guarded: a row of empty tiles reads as "nothing wrong in any
          Function", which is the opposite of "we have not loaded this yet".

          The scope line under the tiles is not decoration. Ten of the 22
          Categories are outside anything an SAP export can answer, and a reader
          who takes this strip for full CSF coverage has been misled by us. */}
      {csfView && (
        <>
          <h2 className={H2}>
            NIST CSF 2.0
            <Link className="ml-2.5 text-[12px] font-normal text-accent hover:underline" to="/csf">
              Full framework view →
            </Link>
          </h2>
          <div className="grid gap-3.5 [grid-template-columns:repeat(auto-fit,minmax(174px,1fr))]">
            {csfView.functions.map((f) => (
              <Link
                key={f.id}
                to={`/csf/${CSF_SLUG[f.id]}`}
                className={`${CARD} csf-rail csf-rail-${f.id} block no-underline hover:bg-panel2`}
              >
                <div className="flex items-center gap-2 mb-2">
                  <span className={`csf csf-${f.id}`}>{f.id}</span>
                  <span className="text-[11px] font-semibold uppercase tracking-[.06em] text-ink2">
                    {f.name}
                  </span>
                </div>
                <div className={`${KPI} text-ink`}>{f.total}</div>
                <div className={KPI_NOTE}>
                  {f.total === 0 && f.categories_assessed > 0
                    ? 'no findings'
                    : `finding${f.total === 1 ? '' : 's'}`}
                  {' · '}
                  {f.categories_assessed}/{f.categories_total} cats
                </div>
              </Link>
            ))}
          </div>
          <p className="text-[12px] text-ink3 mt-2.5">
            {csfView.totals.categories_assessable} of {csfView.totals.categories} CSF
            Categories are assessable from an SAP export;{' '}
            {csfView.totals.categories_not_assessed} describe governance, training and
            incident-response outcomes this product produces no evidence about.{' '}
            <Link className="text-accent hover:underline" to="/csf">See which, and why →</Link>
          </p>
        </>
      )}

      <h2 className={H2}>Systems</h2>
      <div className={`${CARD} p-0 overflow-x-auto`}>
        <table className="w-full border-collapse">
          <thead>
            <tr>
              <th className={TH}>System</th><th className={TH}>Platform</th>
              <th className={TH}>Tier</th><th className={TH}>Criticality</th>
              <th className={TH}>Exposure</th><th className={TH}>Mode</th>
              <th className={TH}>Owner</th>
            </tr>
          </thead>
          <tbody>
            {systems.map((s) => (
              <tr key={s.id} className="hover:bg-panel2">
                {/* `label`, not `sid`: this cell is the only link into the
                    system's findings, and for a tenant `sid` is null — React
                    renders that as an EMPTY anchor, so the row became
                    unclickable with nothing to say why. */}
                <td className={TD}>
                  <Link className="font-mono text-accent" to={`/findings?system_id=${s.id}`}>
                    {s.label}
                  </Link>
                </td>
                <td className={`${TD} text-ink2`}>{s.platform}</td>
                <td className={TD}>{s.tier}</td>
                <td className={TD}>{s.criticality}</td>
                <td className={`${TD} text-ink2`}>{s.exposure_zone}</td>
                <td className={`${TD} text-[12px] text-ink2`}>{s.deployment_mode}</td>
                <td className={`${TD} text-ink2`}>{s.owner ?? '—'}</td>
              </tr>
            ))}
            {systems.length === 0 && (
              <tr>
                <td colSpan={7} className={EMPTY}>
                  No systems registered yet. Upload a bundle to create one.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <h2 className={H2}>Recent scans</h2>
      <div className={`${CARD} p-0 overflow-x-auto`}>
        <table className="w-full border-collapse">
          <thead>
            <tr>
              <th className={TH}>Run</th><th className={TH}>System</th>
              <th className={TH}>Started</th><th className={TH}>Status</th>
              <th className={TH}>Coverage</th><th className={TH}>By</th>
            </tr>
          </thead>
          <tbody>
            {recent_runs.map((r) => (
              <tr key={r.id} className="hover:bg-panel2">
                {/* The ONLY way to reach /runs/:id — it takes an id, so it cannot
                    be in the nav table, and a list that does not link its rows
                    strands the screen below it exactly as an unlisted route would. */}
                <td className={TD}>
                  <Link className="text-accent" to={`/runs/${r.id}`}>#{r.id}</Link>
                </td>
                <td className={`${TD} font-mono`}>
                  {r.sid ?? '—'}{r.client ? `/${r.client}` : ''}
                </td>
                <td className={`${TD} text-ink2 text-[12px]`}>{fmtDateTime(r.started_at)}</td>
                <td className={TD}>
                  <span className={`pill st st-${r.status}`}>{r.status}</span>
                  {IN_FLIGHT.includes(r.status) && r.progress_total > 0 && (
                    <span className="text-ink3 text-[12px] ml-1.5">
                      {r.progress_done}/{r.progress_total}
                    </span>
                  )}
                </td>
                <td className={`${TD} text-[12px] text-ink2`}>{coverageCell(r)}</td>
                <td className={`${TD} text-ink2 text-[12px]`}>{r.uploaded_by ?? '—'}</td>
              </tr>
            ))}
            {recent_runs.length === 0 && (
              <tr><td colSpan={6} className={EMPTY}>No scans yet.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </>
  )
}

// ── the template's classes, as Tailwind ──────────────────────────────────────
// base.html's .card/.kpi/.grid are NOT in index.css: only the chips whose exact
// palette had to survive the port were copied there. These strings reproduce the
// rest locally rather than growing the shared stylesheet from a screen file.
const CSF_SLUG: Record<string, string> = {
  GV: 'govern', ID: 'identify', PR: 'protect',
  DE: 'detect', RS: 'respond', RC: 'recover',
}

const CARD = 'rounded-lg border border-line bg-panel p-4'
const CARD_TITLE = 'mb-3 text-[12px] font-semibold uppercase tracking-[.06em] text-ink3'
const KPI = 'text-[30px] font-semibold tracking-[-.02em] leading-[1.1]'
const KPI_NOTE = 'mt-[5px] text-[12px] text-ink2'
const G4 = 'grid gap-3.5 [grid-template-columns:repeat(auto-fit,minmax(210px,1fr))]'
const G2 = 'grid gap-3.5 [grid-template-columns:repeat(auto-fit,minmax(340px,1fr))]'
const H2 = 'text-[15px] font-semibold mt-[26px] mb-2.5'
const TH = 'text-left px-2.5 py-2 text-[11px] font-semibold uppercase tracking-[.05em] text-ink3 border-b border-line'
const TD = 'px-2.5 py-[9px] align-top border-b border-line'
const EMPTY = 'p-9 text-center text-ink2'

const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

const OWNERS: [RemediationOwner, string][] = [
  ['customer_fixable', 'Yours to fix'],
  ['ticket_to_sap', 'Raise with SAP'],
  ['provider_owned', "SAP's under RISE"],
  ['not_assessable', 'Out of reach in RISE'],
]

const IN_FLIGHT = ['parsing', 'scanning', 'deriving']

/** Coverage is not cosmetic: a missing export file loads as None and its checks
 *  self-skip SILENTLY, so a partial upload otherwise produces a clean-looking
 *  report. `coverage` is free-form jsonb, so every level is checked before use. */
function coverageCell(run: ScanRun) {
  // `coverage` is typed as an object but an older run row can carry SQL NULL, and
  // the template guards it too — index it through the narrowing helper.
  const counts = obj(obj(run.coverage)?.['counts'])
  const supplied = num(counts?.['sources_supplied'])
  const known = num(counts?.['sources_known'])
  if (supplied === null || known === null) return '—'
  const degraded = num(counts?.['modules_degraded'])
  return (
    <>
      {supplied}/{known} sources
      {degraded ? <> · <span className="text-high">{degraded} degraded</span></> : null}
    </>
  )
}

/** '2026-03-14 09:12' — the template's strftime('%Y-%m-%d %H:%M'), in local time.
 *  An unparseable value renders as written rather than as "Invalid Date". */
function fmtDateTime(iso: string | null): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ` +
         `${p(d.getHours())}:${p(d.getMinutes())}`
}

// jsonb columns arrive as `unknown`; these narrow one level at a time so a shape
// change in the scanner degrades to a dash instead of throwing on render.
function obj(v: unknown): Record<string, unknown> | null {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
    ? (v as Record<string, unknown>) : null
}
function num(v: unknown): number | null {
  return typeof v === 'number' && Number.isFinite(v) ? v : null
}
function str(v: unknown): string {
  return typeof v === 'string' ? v : ''
}

/** Branch on the STATUS, never on the message text. */
function describe(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.status === 403) return 'You are not permitted to see this landscape.'
    if (e.status >= 500) return `The server could not answer (${e.status}).`
    return e.message
  }
  return 'The console could not reach the server.'
}
