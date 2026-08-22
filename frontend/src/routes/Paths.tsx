/*
 * Copyright (c) 2026 Krishnendu De. All Rights Reserved.
 *
 * Author : Krishnendu De
 * Coding Assistance : Claude Code
 * Code Security Assistance : Code QL
 */

import { useEffect, useState } from 'react'
import { Link } from 'react-router'
import { ApiError, paths } from '../api/client'
import type { PathsOverview, RemediationOwner } from '../api/types'
import { useTitle } from '../lib/title'
import { UNPRICED_CELL } from '../lib/pricing'
import { money } from './Risk'
import { Waypoints } from 'lucide-react'

/**
 * Risk paths — ported from server/templates/paths.html.
 *
 * THE LANDING SCREEN IS A RANKED LIST AND A CHOKE-POINT TABLE, NOT A GRAPH. Both
 * documented incumbents do the same: the diagram is the evidence pane you open
 * after picking a path (see PathDetail.tsx), and a whole-landscape canvas is a
 * hairball nobody reads. This is also why there is no graph library in the
 * dependency budget — the one diagram in the product is ten nodes of hand-written
 * SVG on the detail screen.
 *
 * EVERY ROW LINKS. A list screen that does not link its rows strands its detail
 * screen exactly as an unlisted route would, and /paths/:id takes an id so it can
 * never have a nav entry of its own.
 */

/** The template's own wording, kept verbatim. "Yours to fix" versus "SAP's" is
 *  the difference between an action and unactionable noise in RISE, and it is
 *  phrased for the customer reading it rather than after the database column. */
const OWNER_LABEL: Record<RemediationOwner, string> = {
  customer_fixable: 'Yours to fix',
  ticket_to_sap: 'Raise with SAP',
  provider_owned: "SAP's",
  not_assessable: 'Out of reach',
}

/** "08 Aug 2026" — `en-GB` for day-then-month, matching the template's `%d %b %Y`. */
function longDate(iso: string | null): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return '—'
  return d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })
}

const CARD = 'rounded-lg border border-cardline bg-panel p-4'
const CARD_H3 = 'text-[12px] font-semibold uppercase tracking-[.06em] text-ink3 mb-3'
const KPI = 'text-[30px] font-semibold tracking-[-.02em] leading-[1.1]'
const KPI_NOTE = 'text-ink2 text-[12px] mt-1.5'
const G4 = 'grid gap-3.5 [grid-template-columns:repeat(auto-fit,minmax(210px,1fr))]'
const H2 = 'text-[15px] font-semibold text-ink mt-7 mb-2.5'
const TH = 'text-left text-[11px] font-semibold uppercase tracking-[.05em] text-ink3 px-2.5 py-2 border-b border-line'
const TD = 'px-2.5 py-2.5 border-b border-line align-top'
const TABLE_CARD = 'rounded-lg border border-cardline bg-panel overflow-x-auto'
const LINK = 'text-accent hover:underline'
const EMPTY = 'p-9 text-center text-ink2'

export function Paths() {
  useTitle('Risk Paths')
  const [view, setView] = useState<PathsOverview | null>(null)
  const [failure, setFailure] = useState<string | null>(null)

  useEffect(() => {
    let live = true
    // Open paths only — `closed` comes back in the same response and is rendered
    // separately below, so asking for them inline would duplicate every severed
    // path into the main list.
    paths()
      .then((v) => { if (live) setView(v) })
      .catch((e: unknown) => {
        if (!live) return
        const status = e instanceof ApiError ? e.status : 0
        setFailure(status === 403
          ? 'Your account is not permitted to see the risk-path model.'
          : `The risk paths could not be loaded${status ? ` (HTTP ${status})` : ''}.`)
      })
    return () => { live = false }
  }, [])

  return (
    <>
      <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2 mb-1">
        <Waypoints size={22} className="text-accent shrink-0" />
        Risk Paths
      </h1>
      <p className="text-ink2 mb-5">
        Conditions that co-exist in your exported configuration and, together, form a route.
      </p>

      {/* Stated on every load, not once and dismissed. Nothing was connected to or
          traversed, and a reader who assumes otherwise draws a far stronger
          conclusion than the evidence carries. */}
      <div className="banner banner-info">
        <strong className="font-[650]">Derived from configuration, not validated.</strong>{' '}
        Nothing was connected to, traversed or reached — these paths are inferred from the
        files you uploaded. Treat them as &ldquo;this route is open&rdquo;, not
        &ldquo;this route was walked&rdquo;.
      </div>

      {failure && <div className="banner banner-bad">{failure}</div>}
      {!failure && view === null && <p className="text-[13px] text-ink3">Loading…</p>}
      {view !== null && <Body view={view} />}
    </>
  )
}

function Body({ view }: { view: PathsOverview }) {
  const { summary, chokepoints, closed } = view

  return (
    <>
      {summary.stale > 0 && (
        <div className="banner banner-warn">
          <strong className="font-[650]">
            {summary.stale} path(s) were derived under an older ruleset.
          </strong>{' '}
          The path templates have changed since they were last computed. Re-scan to refresh
          them — until then they show conclusions the current rules might not draw.
        </div>
      )}

      <div className={G4}>
        <div className={CARD}>
          <h3 className={CARD_H3}>Open paths</h3>
          <div className={`${KPI} ${summary.open ? 'text-crit' : 'text-ok'}`}>
            {summary.open}
          </div>
          <div className={KPI_NOTE}>{summary.critical} critical</div>
        </div>
        <div className={CARD}>
          <h3 className={CARD_H3}>Severed</h3>
          <div className={`${KPI} text-ok`}>{summary.closed}</div>
          <div className={KPI_NOTE}>closed by remediation</div>
        </div>
        <div className={CARD}>
          <h3 className={CARD_H3}>Choke points</h3>
          <div className={KPI}>{chokepoints.length}</div>
          <div className={KPI_NOTE}>single fixes that sever a path</div>
        </div>
        <div className={CARD}>
          <h3 className={CARD_H3}>Templates</h3>
          <div className={KPI}>{view.template_count}</div>
          <div className={KPI_NOTE}>
            a short list is the point — paths cover real routes, not every permutation
          </div>
        </div>
      </div>

      <h2 className={H2}>Choke points</h2>
      <p className="text-ink2 text-[12px] mb-2.5">
        Findings that sit on a <strong className="font-[650]">cut</strong> of one or more
        paths. Closing one of these severs every path it appears on — which is a far
        shorter worklist than the findings queue, with a stated consequence per line.
      </p>
      <div className={TABLE_CARD}>
        <table className="w-full border-collapse">
          <thead>
            <tr>
              <th className={`${TH} w-[80px] text-right`}>Severs</th>
              <th className={`${TH} w-[120px]`}>Check</th>
              <th className={TH}>Title</th>
              <th className={`${TH} w-[100px]`}>System</th>
              <th className={`${TH} w-[120px]`}>Ownership</th>
              <th className={`${TH} w-[90px]`}>State</th>
            </tr>
          </thead>
          <tbody>
            {chokepoints.map((c) => (
              <tr key={c.finding_id} className="hover:bg-panel2">
                <td className={`${TD} text-right`}>
                  {/* Tier colouring by consequence, not by the finding's own tier:
                      a fix that severs more than one path is worth doing first. */}
                  <span className={`tier ${c.paths_cut > 1 ? 'tier-P1' : 'tier-P2'}`}>
                    {c.paths_cut}
                  </span>
                </td>
                <td className={`${TD} font-mono text-[12px]`}>
                  <Link className={LINK} to={`/findings/${c.finding_id}`}>{c.check_id}</Link>
                </td>
                <td className={TD}>
                  {c.title}{' '}
                  <span className="text-ink3 text-[12px]">· {c.scenarios.join(', ')}</span>
                </td>
                <td className={`${TD} font-mono text-[12px]`}>
                  {c.sid ?? '—'}{c.client ? `/${c.client}` : ''}
                </td>
                <td className={TD}>
                  <span className={`own own-${c.remediation_owner}`}>
                    {OWNER_LABEL[c.remediation_owner]}
                  </span>
                </td>
                <td className={TD}>
                  <span className={`pill st st-${c.state}`}>{c.state.replace(/_/g, ' ')}</span>
                </td>
              </tr>
            ))}
            {chokepoints.length === 0 && (
              <tr><td className={EMPTY} colSpan={6}>No choke points — no open paths.</td></tr>
            )}
          </tbody>
        </table>
      </div>

      <h2 className={H2}>Paths</h2>
      <div className={TABLE_CARD}>
        <table className="w-full border-collapse">
          <thead>
            <tr>
              <th className={`${TH} w-[88px]`}>Severity</th>
              <th className={`${TH} w-[110px]`}>Path</th>
              <th className={TH}>Route</th>
              <th className={`${TH} w-[120px] text-right`}>Loss exposure</th>
              <th className={`${TH} w-[80px] text-right`}>Evidence</th>
              <th className={`${TH} w-[90px]`}>Status</th>
            </tr>
          </thead>
          <tbody>
            {view.paths.map((p) => (
              <tr key={p.id} className="hover:bg-panel2">
                <td className={TD}>
                  <span className={`pill sev-${p.severity ?? 'INFO'}`}>{p.severity}</span>
                </td>
                <td className={`${TD} font-mono text-[12px]`}>
                  <Link className={LINK} to={`/paths/${p.id}`}>{p.template_id}</Link>
                </td>
                <td className={TD}>
                  <Link className={LINK} to={`/paths/${p.id}`}>{p.detail.name}</Link>{' '}
                  {p.detail.crosses_tier && (
                    <span className="pill st" title="spans more than one system tier">
                      cross-tier
                    </span>
                  )}
                  <div className="text-[12px] text-ink2">{p.detail.summary}</div>
                </td>
                {/* The path ends at a currency figure. It is the SCENARIO's exposure,
                    not the path's own — a path is evidence that shifts a scenario,
                    never a loss in itself. */}
                {/* An em dash, not $0. The exposure column carries the same figure the
                    money guard governs elsewhere, and a path whose scenario was never
                    priced has no exposure to show — which is not the same as an
                    exposure of nothing. */}
                <td className={`${TD} text-right font-mono`}>
                  {p.scenario_ale ? money(p.scenario_ale) : UNPRICED_CELL}
                </td>
                <td className={`${TD} text-right font-mono text-[12px]`}>{p.finding_count}</td>
                <td className={TD}><span className="pill st st-open">open</span></td>
              </tr>
            ))}
            {view.paths.length === 0 && (
              <tr>
                <td className={EMPTY} colSpan={6}>
                  No open risk paths. That is a legitimate result, not an empty screen —
                  paths are only raised when every required condition genuinely holds.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {closed.length > 0 && (
        <>
          <h2 className={H2}>Recently severed</h2>
          <div className={TABLE_CARD}>
            <table className="w-full border-collapse">
              <thead>
                <tr>
                  <th className={`${TH} w-[110px]`}>Path</th>
                  <th className={TH}>Route</th>
                  <th className={`${TH} w-[140px]`}>Severed</th>
                </tr>
              </thead>
              <tbody>
                {closed.map((p) => (
                  <tr key={p.id} className="hover:bg-panel2">
                    <td className={`${TD} font-mono text-[12px]`}>
                      <Link className={LINK} to={`/paths/${p.id}`}>{p.template_id}</Link>
                    </td>
                    <td className={TD}>{p.detail.name}</td>
                    <td className={`${TD} text-[12px] text-ok`}>{longDate(p.closed_at)}</td>
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
