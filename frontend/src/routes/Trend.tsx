/*
 * Copyright (c) 2026 Krishnendu De. All Rights Reserved.
 *
 * Author : Krishnendu De
 * Coding Assistance : Claude Code
 * Code Security Assistance : Code QL
 */

import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router'
import { ApiError, trend } from '../api/client'
import type { BurndownPoint, Journey } from '../api/types'
import { useTitle } from '../lib/title'
import { TrendingUp } from 'lucide-react'

/**
 * The mitigation journey — ported from server/templates/trend.html. It answers
 * "is it getting better" without anyone exporting anything.
 *
 * THE WINDOW LIVES IN THE ADDRESS BAR, not in React state. `days` is in
 * queries.VIEW_FILTER_KEYS and a saved view of kind 'trend' redirects here
 * carrying it, so the URL is the authoritative filter — and saveView() reads the
 * filters off the HTTP Referer, meaning a window held only in component state
 * would be saved as an empty view and fail silently.
 *
 * WHOSE CLOCK IS WHOSE. Overdue work is reported twice, split by remediation
 * owner, and never added together: rolling provider-bound findings into the
 * customer's breach count measures the wrong organisation, and in RISE a large
 * share of the queue is work the customer is not permitted to do.
 *
 * COUNTS, NOT AVERAGES, in the trajectory. A mean severity that falls because a
 * batch of LOW findings arrived would say nothing was fixed.
 */

/** The windows offered as buttons. Any other value in the URL is honoured and
 *  fetched as-is — a saved view carrying days=45 must keep working — it simply
 *  does not light one of these up. */
const WINDOWS = [30, 90, 180, 365]
const DEFAULT_DAYS = 180   // server/app.py api_trend's own default

function shortDate(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return '—'
  return d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short' })
}

/** Days rendered as "12d", or an em dash when the aggregate had nothing to
 *  average. The Jinja page prints "—d" here; "not measured" reads better without
 *  a unit stuck to it. */
function days(value: number | null): string {
  return value === null ? '—' : `${value}d`
}

const CARD = 'rounded-lg border border-cardline bg-panel p-4'
const CARD_H3 = 'text-[12px] font-semibold uppercase tracking-[.06em] text-ink3 mb-3'
const KPI = 'text-[30px] font-semibold tracking-[-.02em] leading-[1.1]'
const KPI_NOTE = 'text-ink2 text-[12px] mt-1.5'
const G4 = 'grid gap-3.5 [grid-template-columns:repeat(auto-fit,minmax(210px,1fr))]'
const G2 = 'grid gap-3.5 mt-3.5 [grid-template-columns:repeat(auto-fit,minmax(340px,1fr))]'
const H2 = 'text-[15px] font-semibold text-ink mt-7 mb-2.5'
const TH = 'text-left text-[11px] font-semibold uppercase tracking-[.05em] text-ink3 px-2.5 py-2 border-b border-line'
const TD = 'px-2.5 py-2.5 border-b border-line align-top'
const TABLE_CARD = 'rounded-lg border border-cardline bg-panel overflow-x-auto'
const LINK = 'text-accent hover:underline'
const EMPTY = 'p-9 text-center text-ink2'

export function Trend() {
  useTitle('Trend')
  const [params, setParams] = useSearchParams()
  const parsed = Number(params.get('days'))
  const window = Number.isFinite(parsed) && parsed > 0 ? Math.trunc(parsed) : DEFAULT_DAYS

  const [journey, setJourney] = useState<Journey | null>(null)
  const [failure, setFailure] = useState<string | null>(null)

  useEffect(() => {
    let live = true
    setJourney(null)
    setFailure(null)
    trend(window)
      .then((j) => { if (live) setJourney(j) })
      .catch((e: unknown) => {
        if (!live) return
        const status = e instanceof ApiError ? e.status : 0
        setFailure(status === 403
          ? 'Your account is not permitted to see the mitigation journey.'
          : `The mitigation journey could not be loaded${status ? ` (HTTP ${status})` : ''}.`)
      })
    return () => { live = false }
  }, [window])

  return (
    <>
      <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2 mb-1">
        <TrendingUp size={22} className="text-accent shrink-0" />
        Mitigation Journey
      </h1>
      <p className="text-ink2 mb-4">
        What changed, who owns it, and whether it is getting better — over the last{' '}
        {window} days.
      </p>

      <div className="flex gap-1.5 items-center mb-5">
        <span className="text-[11px] uppercase tracking-[.05em] text-ink3 mr-1">Window</span>
        {WINDOWS.map((d) => (
          <button
            key={d}
            type="button"
            className={d === window ? 'btn' : 'btn btn-ghost'}
            onClick={() => setParams((prev) => {
              // Merge rather than replace: the window is one filter among whatever
              // else a saved view put in the URL, and saveView() will read all of
              // them back off the Referer.
              const next = new URLSearchParams(prev)
              next.set('days', String(d))
              return next
            })}
          >
            {d}d
          </button>
        ))}
      </div>

      {failure && <div className="banner banner-bad">{failure}</div>}
      {!failure && journey === null && <p className="text-[13px] text-ink3">Loading…</p>}
      {journey !== null && <Body j={journey} />}
    </>
  )
}

function Body({ j }: { j: Journey }) {
  const sla = j.sla
  const debt = j.technical_debt
  const mttrByTeam = new Map(j.mttr.by_team.map((m) => [m.team, m]))

  return (
    <>
      <div className={G4}>
        <div className={CARD}>
          <h3 className={CARD_H3}>Overdue — yours</h3>
          <div className={`${KPI} ${sla.overdue_customer ? 'text-crit' : 'text-ok'}`}>
            {sla.overdue_customer}
          </div>
          <div className={KPI_NOTE}>{sla.due_soon_customer} due within 7 days</div>
        </div>
        <div className={CARD}>
          <h3 className={CARD_H3}>Overdue — with SAP</h3>
          <div className={`${KPI} ${sla.overdue_provider ? 'text-high' : ''}`}>
            {sla.overdue_provider}
          </div>
          {/* Reported separately on purpose. Rolling provider-bound work into the
              customer's breach count measures the wrong organisation. */}
          <div className={KPI_NOTE}>provider queue, not your clock</div>
        </div>
        <div className={CARD}>
          <h3 className={CARD_H3}>Mean time to remediate</h3>
          <div className={KPI}>
            {j.mttr.overall?.mean_days ?? '—'}
            <span className="text-ink2 text-[15px]">d</span>
          </div>
          <div className={KPI_NOTE}>over {j.mttr.overall?.resolved ?? 0} resolved</div>
        </div>
        <div className={CARD}>
          <h3 className={CARD_H3}>Open &gt; 90 days</h3>
          <div className={`${KPI} ${debt.stale_over_90d ? 'text-high' : ''}`}>
            {debt.stale_over_90d}
          </div>
          <div className={KPI_NOTE}>accumulated technical debt</div>
        </div>
      </div>

      <h2 className={H2}>Backlog trajectory</h2>
      <Burndown points={j.burndown} />

      <div className={G2}>
        <div className={CARD}>
          <h3 className={CARD_H3}>Backlog by priority</h3>
          <table className="w-full border-collapse">
            <thead>
              <tr>
                <th className={TH}>Tier</th>
                <th className={`${TH} text-right`}>Open</th>
                <th className={`${TH} text-right`}>Overdue</th>
                <th className={`${TH} text-right`}>With SAP</th>
                <th className={`${TH} text-right`}>Avg age</th>
              </tr>
            </thead>
            <tbody>
              {j.backlog_by_tier.map((t) => (
                <tr key={t.tier} className="hover:bg-panel2">
                  <td className={TD}>
                    <Link className={LINK} to={`/findings?tier=${encodeURIComponent(t.tier)}`}>
                      <strong className="font-[650]">{t.tier}</strong>
                    </Link>
                  </td>
                  <td className={`${TD} text-right font-mono`}>{t.open}</td>
                  <td className={`${TD} text-right font-mono ${t.overdue ? 'text-crit' : ''}`}>
                    {t.overdue}
                  </td>
                  <td className={`${TD} text-right font-mono text-ink2`}>{t.with_sap}</td>
                  <td className={`${TD} text-right font-mono text-ink2`}>
                    {days(t.avg_age_days)}
                  </td>
                </tr>
              ))}
              {j.backlog_by_tier.length === 0 && (
                <tr><td className={EMPTY} colSpan={5}>No open findings.</td></tr>
              )}
            </tbody>
          </table>
        </div>

        <div className={CARD}>
          <h3 className={CARD_H3}>Time to remediate, by severity</h3>
          <table className="w-full border-collapse">
            <thead>
              <tr>
                <th className={TH}>Severity</th>
                <th className={`${TH} text-right`}>Resolved</th>
                <th className={`${TH} text-right`}>Mean</th>
                <th className={`${TH} text-right`}>Median</th>
              </tr>
            </thead>
            <tbody>
              {j.mttr.by_severity.map((m) => (
                <tr key={m.severity ?? 'none'} className="hover:bg-panel2">
                  <td className={TD}>
                    <span className={`pill sev-${m.severity ?? 'INFO'}`}>{m.severity}</span>
                  </td>
                  <td className={`${TD} text-right font-mono`}>{m.resolved}</td>
                  <td className={`${TD} text-right font-mono`}>{days(m.mean_days)}</td>
                  <td className={`${TD} text-right font-mono text-ink2`}>
                    {days(m.median_days)}
                  </td>
                </tr>
              ))}
              {j.mttr.by_severity.length === 0 && (
                <tr>
                  <td className={EMPTY} colSpan={4}>
                    Nothing resolved in this window yet. MTTR counts findings actually
                    closed — including still-open ones would make it fall whenever new
                    findings arrive.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <h2 className={H2}>Who owns the work</h2>
      <div className={TABLE_CARD}>
        <table className="w-full border-collapse">
          <thead>
            <tr>
              <th className={TH}>Team</th>
              <th className={`${TH} text-right`}>Open</th>
              <th className={`${TH} text-right`}>Critical</th>
              <th className={`${TH} text-right`}>High</th>
              <th className={`${TH} text-right`}>Overdue</th>
              <th className={`${TH} text-right`}>Actionable now</th>
              <th className={`${TH} text-right`}>Avg age</th>
              <th className={`${TH} text-right`}>MTTR</th>
            </tr>
          </thead>
          <tbody>
            {j.teams.map((t) => (
              <tr key={t.team} className="hover:bg-panel2">
                <td className={TD}>
                  <Link className={LINK} to={`/findings?team=${encodeURIComponent(t.team)}`}>
                    {t.team.replace(/_/g, ' ')}
                  </Link>
                </td>
                <td className={`${TD} text-right font-mono`}>{t.open}</td>
                <td className={`${TD} text-right font-mono ${t.critical ? 'text-crit' : ''}`}>
                  {t.critical}
                </td>
                <td className={`${TD} text-right font-mono`}>{t.high}</td>
                <td className={`${TD} text-right font-mono ${t.overdue ? 'text-crit' : ''}`}>
                  {t.overdue}
                </td>
                {/* "Actionable now" excludes findings only SAP can change — otherwise a
                    team looks like it is ignoring work it is not permitted to do. */}
                <td className={`${TD} text-right font-mono text-ok`}>{t.actionable}</td>
                <td className={`${TD} text-right font-mono text-ink2`}>
                  {days(t.avg_age_days)}
                </td>
                <td className={`${TD} text-right font-mono text-ink2`}>
                  {days(mttrByTeam.get(t.team)?.mean_days ?? null)}
                </td>
              </tr>
            ))}
            {j.teams.length === 0 && (
              <tr><td className={EMPTY} colSpan={8}>No open findings.</td></tr>
            )}
          </tbody>
        </table>
      </div>

      <h2 className={H2}>Pass rate by finding category</h2>
      <div className={TABLE_CARD}>
        <table className="w-full border-collapse">
          <thead>
            <tr>
              <th className={TH}>Category</th>
              <th className={`${TH} w-[36%]`}>Checks passing</th>
              <th className={`${TH} text-right`}>Checks</th>
              <th className={`${TH} text-right`}>Failing</th>
            </tr>
          </thead>
          <tbody>
            {j.domains.map((d) => {
              // A CATEGORY NOTHING ASSESSED HAS NO PERCENTAGE, and `?? 0` turned
              // that into the worst possible score — a category whose export was
              // never supplied rendered as 0% and sorted to the top of the table
              // as the customer's biggest problem.
              const pct = d.pct_passing
              // NOT A TRAFFIC LIGHT, AND NOT CALLED "COMPLIANT".
              //
              // Two separate problems, and only one of them was the word. The
              // column read "Compliant", which claims conformance with something
              // external; this is the pass rate over the checks that actually ran,
              // which is a statement about our own checks and nothing else.
              //
              // The column was fixed first and the field behind it was not, so
              // `pct_compliant` went on saying in JSON what the screen had stopped
              // saying in English. It is `pct_passing` now, everywhere.
              //
              // The colour was worse. green >= 80 / amber >= 60 / red asserts that
              // eighty per cent passing is a good result, and it is SEVERITY-BLIND:
              // a category with sixteen passes and four CRITICAL failures rendered
              // green while being on fire. The bar is now neutral and the failing
              // count beside it carries the weight, because that column already
              // links to the findings themselves.
              const fill = 'var(--ink-faint)'
              return (
                <tr key={d.category ?? 'uncategorised'} className="hover:bg-panel2">
                  <td className={TD}>
                    {d.category === null
                      ? <span className="text-ink3">uncategorised</span>
                      : (
                        <Link className={LINK}
                              to={`/findings?category=${encodeURIComponent(d.category)}`}>
                          {d.category}
                        </Link>
                      )}
                  </td>
                  <td className={TD}>
                    {pct === null ? (
                      <span className="csf-state csf-state-not_supplied">not assessed</span>
                    ) : (
                      <div className="flex items-center gap-2">
                        <div className="flex-1 h-1.5 rounded-[3px] bg-panel2 overflow-hidden">
                          <i className="block h-full"
                             style={{ width: `${pct}%`, background: fill }} />
                        </div>
                        <span className="font-mono text-[12px] w-[38px] text-right">{pct}%</span>
                      </div>
                    )}
                  </td>
                  <td className={`${TD} text-right font-mono text-ink2`}>{d.checks_known}</td>
                  <td className={`${TD} text-right font-mono`}>{d.checks_failing}</td>
                </tr>
              )
            })}
            {j.domains.length === 0 && (
              <tr><td className={EMPTY} colSpan={4}>No findings yet.</td></tr>
            )}
          </tbody>
        </table>
        <p className="text-[12px] text-ink3 px-3.5 py-2.5 m-0">
          Scored over checks that actually ran for these systems, not the whole catalogue —
          otherwise supplying fewer exports would improve the score.
        </p>
      </div>

      <h2 className={H2}>Aging</h2>
      <div className={TABLE_CARD}>
        <table className="w-full border-collapse">
          <thead>
            <tr>
              <th className={TH}>Severity</th>
              <th className={`${TH} text-right`}>0–7d</th>
              <th className={`${TH} text-right`}>7–30d</th>
              <th className={`${TH} text-right`}>30–90d</th>
              <th className={`${TH} text-right`}>90d+</th>
              <th className={`${TH} text-right`}>Total</th>
              <th className={`${TH} text-right`}>Avg</th>
            </tr>
          </thead>
          <tbody>
            {j.aging.map((a) => (
              <tr key={a.severity ?? 'none'} className="hover:bg-panel2">
                <td className={TD}>
                  <span className={`pill sev-${a.severity ?? 'INFO'}`}>{a.severity}</span>
                </td>
                <td className={`${TD} text-right font-mono text-ink2`}>{a.d0_7}</td>
                <td className={`${TD} text-right font-mono text-ink2`}>{a.d7_30}</td>
                <td className={`${TD} text-right font-mono`}>{a.d30_90}</td>
                <td className={`${TD} text-right font-mono ${a.d90_plus ? 'text-crit' : ''}`}>
                  {a.d90_plus}
                </td>
                <td className={`${TD} text-right font-mono`}>{a.total}</td>
                <td className={`${TD} text-right font-mono text-ink2`}>{days(a.avg_days)}</td>
              </tr>
            ))}
            {j.aging.length === 0 && (
              <tr><td className={EMPTY} colSpan={7}>No open findings.</td></tr>
            )}
          </tbody>
        </table>
      </div>

      {debt.recurring.length > 0 && (
        <>
          <h2 className={H2}>Recurring defects</h2>
          <div className="banner banner-warn">
            These were fixed and came back. A defect that returns is a{' '}
            <strong className="font-[650]">process</strong> failure, not a backlog item —
            and it is invisible if you only look at current state.
          </div>
          <div className={TABLE_CARD}>
            <table className="w-full border-collapse">
              <thead>
                <tr>
                  <th className={`${TH} w-[88px]`}>Severity</th>
                  <th className={`${TH} w-[130px]`}>Check</th>
                  <th className={TH}>Title</th>
                  <th className={`${TH} w-[100px]`}>System</th>
                  <th className={`${TH} w-[90px] text-right`}>Times back</th>
                </tr>
              </thead>
              <tbody>
                {debt.recurring.map((r) => (
                  <tr key={r.id} className="hover:bg-panel2">
                    <td className={TD}>
                      <span className={`pill sev-${r.severity ?? 'INFO'}`}>{r.severity}</span>
                    </td>
                    <td className={`${TD} font-mono text-[12px]`}>
                      <Link className={LINK} to={`/findings/${r.id}`}>{r.check_id}</Link>
                    </td>
                    <td className={TD}>{r.title}</td>
                    <td className={`${TD} font-mono text-[12px] text-ink2`}>{r.sid ?? '—'}</td>
                    <td className={`${TD} text-right font-mono text-high`}>
                      {r.regression_count}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {debt.expired_acceptances.length > 0 && (
        <>
          <h2 className={H2}>Expired risk acceptances</h2>
          <div className="banner banner-bad">
            An acceptance that has passed its expiry is itself an audit finding — the defect
            is open and the time-box has run out.
          </div>
          <div className={TABLE_CARD}>
            <table className="w-full border-collapse">
              <thead>
                <tr>
                  <th className={`${TH} w-[130px]`}>Check</th>
                  <th className={TH}>Title</th>
                  <th className={`${TH} w-[140px]`}>Accepted by</th>
                  <th className={`${TH} w-[110px]`}>Expired</th>
                </tr>
              </thead>
              <tbody>
                {debt.expired_acceptances.map((a) => (
                  <tr key={a.id} className="hover:bg-panel2">
                    <td className={`${TD} font-mono text-[12px]`}>
                      <Link className={LINK} to={`/findings/${a.id}`}>{a.check_id}</Link>
                    </td>
                    <td className={TD}>{a.title}</td>
                    <td className={`${TD} text-[12px] text-ink2`}>{a.accepted_by ?? '—'}</td>
                    <td className={`${TD} text-[12px] text-crit`}>{a.acceptance_due ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </>
  )
}

/**
 * Open findings after each scan.
 *
 * PER RUN, NOT PER CALENDAR DAY. The backlog only changes when a scan observes
 * it, so a daily series over weekly scans would draw six flat days and a cliff,
 * implying activity on days nothing was measured. One bar per run says exactly
 * what was measured and when.
 *
 * Hidden below two points: a single bar is not a trajectory, and the empty state
 * says which one it is — "not enough history yet" rather than a chart of nothing.
 */
function Burndown({ points }: { points: BurndownPoint[] }) {
  if (points.length <= 1) {
    return (
      <div className={CARD}>
        <div className={EMPTY}>
          Not enough history yet — the trajectory appears after a second completed scan.
        </div>
      </div>
    )
  }
  const max = Math.max(...points.map((p) => p.open_after))

  return (
    <div className={CARD}>
      <div className="flex items-end gap-1.5 h-[150px] py-2 overflow-x-auto">
        {points.map((b) => (
          <div key={b.run_id} className="flex flex-col items-center gap-1 min-w-[44px]">
            <span className="text-[12px] font-mono text-ink3">{b.open_after}</span>
            <div className="w-[26px] rounded-t-[3px] bg-accent"
                 style={{ height: max ? `${Math.round(110 * b.open_after / max)}px` : '2px' }}
                 title={`run #${b.run_id}: ${b.open_after} open, ${b.new} new`} />
            {b.critical > 0 && (
              <div className="w-[26px] rounded-b-[3px] bg-crit"
                   style={{ height: max ? `${Math.round(110 * b.critical / max)}px` : '1px' }}
                   title={`${b.critical} critical`} />
            )}
            <span className="text-[10px] text-ink3">{shortDate(b.started_at)}</span>
          </div>
        ))}
      </div>
      <p className="text-[12px] text-ink3 mt-1.5 mb-0">
        Blue = open findings after each scan · red = critical. Counts of open findings,
        never an average severity: a mean that falls because a batch of LOW findings
        arrived would say nothing was fixed.
      </p>
    </div>
  )
}
