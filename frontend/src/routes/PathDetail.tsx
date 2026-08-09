import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router'
import { ApiError, path as fetchPath } from '../api/client'
import type { PathFinding, PathHop, PathView, RemediationOwner } from '../api/types'
import { useTitle } from '../lib/title'
import { money } from './Risk'

/**
 * One attack path with its evidence — ported from server/templates/path_detail.html.
 *
 * THE GRAPH RENDERS ONLY HERE, at six to ten nodes, inside a path someone chose to
 * open. It is hand-written SVG for the same reason the dependency budget has no
 * chart library: this is the only diagram in the product, it is a row of boxes and
 * arrows, and a graph library would be the largest thing in the bundle by an order
 * of magnitude.
 *
 * THE CUT DISTINCTION IS THE SCREEN. A finding on a cut hop severs the path; a
 * finding on any other hop reduces exploitability without ending anything. It is
 * drawn three times — in the diagram, in the steps table, and as the two-column
 * remediation split — because flattening it back into one list of findings is
 * exactly what the findings queue already does, and would leave this screen with
 * nothing to say.
 *
 * `cut_ids` COMES FROM THE SERVER and is not recomputed here: the Jinja page and
 * this one must make the same call about which findings actually end the attack,
 * and two implementations of that rule would eventually disagree.
 */

const OWNER_SHORT: Record<RemediationOwner, string> = {
  customer_fixable: 'yours',
  ticket_to_sap: 'SAP',
  provider_owned: "SAP's",
  not_assessable: 'out of reach',
}

/** Authored text carries its structure in newlines and HTML throws them away.
 *  Transcribed from server/prose.py `paragraphs`: one paragraph per non-empty
 *  line, never a blank-line split — the corpus does not use blank lines, so a
 *  blank-line split would return the whole narrative as one wall of text.
 *
 *  No template in data/attack_paths.json contains a newline today, so this changes
 *  nothing on screen. It is here so the first multi-paragraph narrative someone
 *  writes does not silently collapse, which is exactly how the remediation panel
 *  on the finding screen broke. */
function paragraphs(text: string | null | undefined): string[] {
  if (!text) return []
  return text.split('\n').map((l) => l.trim()).filter((l) => l !== '')
}

function dayMonthYear(iso: string | null, month: 'short' | 'long' = 'short'): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return '—'
  return d.toLocaleDateString('en-GB', { day: '2-digit', month, year: 'numeric' })
}

const CARD = 'rounded-lg border border-line bg-panel p-4'
const CARD_H3 = 'text-[12px] font-semibold uppercase tracking-[.06em] text-ink3 mb-3'
const G2 = 'grid gap-3.5 [grid-template-columns:repeat(auto-fit,minmax(340px,1fr))]'
const H2 = 'text-[15px] font-semibold text-ink mt-7 mb-2.5'
const TH = 'text-left text-[11px] font-semibold uppercase tracking-[.05em] text-ink3 px-2.5 py-2 border-b border-line'
const TD = 'px-2.5 py-2.5 border-b border-line align-top'
const TABLE_CARD = 'rounded-lg border border-line bg-panel overflow-x-auto'
const LINK = 'text-accent hover:underline'

export function PathDetail() {
  const { id } = useParams()
  const [view, setView] = useState<PathView | null>(null)
  const [failure, setFailure] = useState<string | null>(null)

  // The template id, as path_detail.html's `{% block title %}` does. null while
  // it loads so the paths list's title stays up instead of blinking.
  useTitle(view?.path.template_id ?? null)

  useEffect(() => {
    let live = true
    setView(null)
    setFailure(null)
    fetchPath(Number(id))
      .then((v) => { if (live) setView(v) })
      .catch((e: unknown) => {
        if (!live) return
        const status = e instanceof ApiError ? e.status : 0
        // The server answers 404 both for "no such path" and "in a landscape you
        // cannot see", deliberately — distinguishing them would let a scoped user
        // enumerate ids. The message says so rather than implying the path is gone.
        setFailure(status === 404
          ? 'No such attack path — it does not exist, or it belongs to a landscape outside your scope.'
          : `This attack path could not be loaded${status ? ` (HTTP ${status})` : ''}.`)
      })
    return () => { live = false }
  }, [id])

  return (
    <>
      <p className="text-[12px] mb-2">
        <Link className={LINK} to="/paths">&larr; Attack paths</Link>
      </p>
      {failure && <div className="banner banner-bad">{failure}</div>}
      {!failure && view === null && <p className="text-[13px] text-ink3">Loading…</p>}
      {view !== null && <Body view={view} />}
    </>
  )
}

function Body({ view }: { view: PathView }) {
  const { path, findings } = view
  const d = path.detail
  // `?? []` rather than a trust in the type: `detail` is jsonb written by
  // graph.py, and server/app.py reads it back as `.get("hops") or []` for the
  // same reason. A path row stored by an older ruleset without hops should cost
  // the diagram, not the whole screen.
  const hops = d.hops ?? []
  const cut = new Set(view.cut_ids)
  const severing = findings.filter((f) => cut.has(f.id))
  const contributing = findings.filter((f) => !cut.has(f.id))

  return (
    <>
      <h1 className="text-[21px] font-semibold tracking-tight text-ink mb-1">
        <span className={`pill sev-${path.severity ?? 'INFO'}`}>{path.severity}</span>{' '}
        {d.name}
      </h1>
      <p className="text-ink2 mb-5">
        <span className="font-mono">{path.template_id}</span>
        {' · ends at '}<span className="font-mono">{path.fair_scenario}</span>
        {path.scenario_ale ? ` · exposure ${money(path.scenario_ale)}` : ''}
        {` · first seen ${dayMonthYear(path.first_seen)}`}
      </p>

      {path.closed_at !== null && (
        <div className="banner banner-ok">
          <strong className="font-[650]">
            Severed on {dayMonthYear(path.closed_at, 'long')}.
          </strong>{' '}
          The conditions that formed this route no longer all hold. The row is kept rather
          than deleted, so the path can be shown to have closed — and would re-open with
          its history intact if the conditions returned.
        </div>
      )}

      <div className="banner banner-info">
        <strong className="font-[650]">{d.confidence_note}</strong>
      </div>

      <div className={CARD}>
        {paragraphs(d.narrative).map((para, i) => (
          <p key={i} className="mb-2.5 last:mb-0">{para}</p>
        ))}
      </div>

      <h2 className={H2}>The route</h2>
      <RouteDiagram hops={hops} />

      <h2 className={H2}>Steps</h2>
      {/* The tabular view alongside the diagram: step / object / why this step works
          is what a Basis reviewer actually pastes into a change ticket, and it
          renders from stored data with no graph library. */}
      <div className={TABLE_CARD}>
        <table className="w-full border-collapse">
          <thead>
            <tr>
              <th className={`${TH} w-[34px]`}>#</th>
              <th className={TH}>Step</th>
              <th className={`${TH} w-[84px]`}>Required</th>
              <th className={`${TH} w-[70px]`}>Cut</th>
              <th className={`${TH} w-[90px] text-right`}>Evidence</th>
            </tr>
          </thead>
          <tbody>
            {hops.map((h, i) => (
              <tr key={`${i}-${h.name}`} className="hover:bg-panel2">
                <td className={`${TD} font-mono text-[12px] text-ink3`}>{i + 1}</td>
                <td className={TD}>
                  <strong className="font-[650]">{h.name}</strong>
                  {h.why_cut && <div className="text-[12px] text-ink2">{h.why_cut}</div>}
                  <div className="text-[12px] text-ink3 font-mono">{h.checks.join(' · ')}</div>
                </td>
                <td className={`${TD} text-[12px]`}>
                  {h.required ? 'required' : 'contributing'}
                </td>
                <td className={TD}>
                  {h.is_cut
                    ? <span className="pill sev-CRITICAL">cut</span>
                    : <span className="text-ink3 text-[12px]">—</span>}
                </td>
                <td className={`${TD} text-right font-mono text-[12px]`}>
                  {h.present ? h.evidence_total : <span className="text-ink3">none</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <h2 className={H2}>Remediation</h2>
      {/* The mitigate-vs-additional split, which is what makes a path actionable. It
          needs no clever algorithm — only that each hop knows whether removing it
          disconnects the route. */}
      <div className={G2}>
        <div className={CARD}>
          <h3 className={`${CARD_H3} text-crit`}>Severs this path</h3>
          <p className="text-[12px] text-ink2 -mt-1 mb-2.5">
            Close any one of these and the route is gone.
          </p>
          <table className="w-full border-collapse">
            <tbody>
              {severing.map((f) => (
                <tr key={f.id} className="hover:bg-panel2">
                  <td className={`${TD} w-[118px] font-mono text-[12px]`}>
                    <Link className={LINK} to={`/findings/${f.id}`}>{f.check_id}</Link>
                  </td>
                  <td className={TD}>
                    {f.title}{' '}
                    <span className={`own own-${f.remediation_owner}`}>
                      {OWNER_SHORT[f.remediation_owner]}
                    </span>
                  </td>
                </tr>
              ))}
              {severing.length === 0 && (
                <tr>
                  <td className="px-2.5 py-2.5 text-[12px] text-ink2">
                    No cut is currently open for this path.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <div className={CARD}>
          <h3 className={CARD_H3}>Reduces risk, but does not sever</h3>
          <p className="text-[12px] text-ink2 -mt-1 mb-2.5">
            Worth doing. Will not close the route on its own.
          </p>
          <table className="w-full border-collapse">
            <tbody>
              {contributing.map((f) => (
                <tr key={f.id} className="hover:bg-panel2">
                  <td className={`${TD} w-[118px] font-mono text-[12px]`}>
                    <Link className={LINK} to={`/findings/${f.id}`}>{f.check_id}</Link>
                  </td>
                  <td className={TD}>{f.title}</td>
                </tr>
              ))}
              {contributing.length === 0 && (
                <tr><td className="px-2.5 py-2.5 text-[12px] text-ink2">—</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <h2 className={H2}>All evidence</h2>
      <div className={TABLE_CARD}>
        <table className="w-full border-collapse">
          <thead>
            <tr>
              <th className={`${TH} w-[88px]`}>Severity</th>
              <th className={`${TH} w-[118px]`}>Check</th>
              <th className={TH}>Title</th>
              <th className={`${TH} w-[100px]`}>System</th>
              <th className={`${TH} w-[90px]`}>State</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f) => <EvidenceRow key={f.id} f={f} />)}
            {findings.length === 0 && (
              <tr>
                <td className="p-9 text-center text-ink2" colSpan={5}>
                  No findings are currently attached to this path.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </>
  )
}

function EvidenceRow({ f }: { f: PathFinding }) {
  return (
    <tr className="hover:bg-panel2">
      <td className={TD}>
        <span className={`pill sev-${f.severity ?? 'INFO'}`}>{f.severity}</span>
      </td>
      <td className={`${TD} font-mono text-[12px]`}>
        <Link className={LINK} to={`/findings/${f.id}`}>{f.check_id}</Link>
      </td>
      <td className={TD}>{f.title}</td>
      <td className={`${TD} font-mono text-[12px]`}>
        {f.sid ?? '—'}{f.client ? `/${f.client}` : ''}
      </td>
      <td className={TD}>
        <span className={`pill st st-${f.state}`}>{f.state.replace(/_/g, ' ')}</span>
      </td>
    </tr>
  )
}

/**
 * The route, drawn.
 *
 * Geometry is the template's, unchanged: 190px of horizontal pitch per hop, a
 * 156×56 box, and a fixed 132-unit viewBox height. It scales with the hop count
 * rather than the viewport because a six-hop path squeezed into a phone width
 * stops being readable long before it stops fitting — hence the min-width and the
 * horizontal scroll on the card instead.
 *
 * THE THREE VISUAL STATES CARRY MEANING and are stated in the legend rather than
 * left to be inferred: solid is a condition that holds, dashed is one that is not
 * present, and red is a cut. A viewer who reads dashed as "less important" rather
 * than "not currently true" would misread the entire diagram.
 */
function RouteDiagram({ hops }: { hops: PathHop[] }) {
  const width = 60 + hops.length * 190
  return (
    <div className="rounded-lg border border-line bg-panel p-4 overflow-x-auto">
      <svg viewBox={`0 0 ${width} 132`} width="100%"
           style={{ maxWidth: `${width}px`, minWidth: '520px' }}
           role="img" aria-label="Attack path diagram">
        <defs>
          <marker id="ar" markerWidth="9" markerHeight="7" refX="9" refY="3.5" orient="auto">
            <polygon points="0 0, 9 3.5, 0 7" fill="var(--ink-faint)" />
          </marker>
        </defs>
        {hops.map((h, i) => {
          const x = 30 + i * 190
          const dash = h.present ? undefined : '4 3'
          const cut = h.is_cut && h.present
          return (
            <g key={`${i}-${h.name}`}>
              {i > 0 && (
                <line x1={x - 34} y1={52} x2={x - 8} y2={52}
                      stroke="var(--ink-faint)" strokeWidth={1.5}
                      markerEnd="url(#ar)" strokeDasharray={dash} />
              )}
              <rect x={x} y={24} width={156} height={56} rx={7}
                    fill={cut ? 'rgba(244,63,94,.13)'
                              : h.present ? 'var(--panel-2)' : 'transparent'}
                    stroke={cut ? 'var(--crit)' : 'var(--line)'}
                    strokeWidth={cut ? 2 : 1} strokeDasharray={dash} />
              <text x={x + 10} y={44} fontSize={10.5} fill="var(--ink)">
                {h.name.slice(0, 24)}
              </text>
              <text x={x + 10} y={59} fontSize={9.5} fill="var(--ink-dim)">
                {h.name.slice(24, 46)}
              </text>
              <text x={x + 10} y={73} fontSize={9} fill="var(--ink-faint)">
                {h.present ? `${h.evidence_total} finding(s)` : 'not present'}
              </text>
              {cut && (
                <text x={x + 10} y={17} fontSize={9} fontWeight={700} fill="var(--crit)">
                  CUT — closing this severs the path
                </text>
              )}
            </g>
          )
        })}
        <text x={30} y={112} fontSize={9.5} fill="var(--ink-faint)">
          Solid = condition holds. Dashed = not present. Red = a cut.
        </text>
      </svg>
    </div>
  )
}
