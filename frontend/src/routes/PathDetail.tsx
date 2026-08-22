/*
 * Copyright (c) 2026 Krishnendu De. All Rights Reserved.
 *
 * Author : Krishnendu De
 * Coding Assistance : Claude Code
 * Code Security Assistance : Code QL
 */

import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router'
import { ApiError, path as fetchPath } from '../api/client'
import type { PathFinding, PathHop, PathView, RemediationOwner } from '../api/types'
import { useTitle } from '../lib/title'
import { money } from './Risk'
import { Waypoints } from 'lucide-react'

/**
 * One risk path with its evidence — ported from server/templates/path_detail.html.
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
          ? 'No such risk path — it does not exist, or it belongs to a landscape outside your scope.'
          : `This risk path could not be loaded${status ? ` (HTTP ${status})` : ''}.`)
      })
    return () => { live = false }
  }, [id])

  return (
    <>
      <p className="text-[12px] mb-2">
        <Link className={LINK} to="/paths">&larr; Risk paths</Link>
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
  // Shared by the diagram and the steps table, so the two views of the same list
  // agree about what the reader is looking at. Selecting is a toggle: clicking the
  // step you already chose clears it rather than trapping the highlight.
  const [selected, setSelected] = useState<number | null>(null)
  const pick = (i: number) => setSelected((cur) => (cur === i ? null : i))
  const cut = new Set(view.cut_ids)
  const severing = findings.filter((f) => cut.has(f.id))
  const contributing = findings.filter((f) => !cut.has(f.id))

  return (
    <>
      <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2 mb-1">
        <Waypoints size={22} className="text-accent shrink-0" />
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
      <RouteDiagram hops={hops} scenario={path.fair_scenario} ale={path.scenario_ale}
                    selected={selected} onSelect={pick} />

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
              <tr key={`${i}-${h.name}`}
                  onClick={() => pick(i)}
                  className={`cursor-pointer ${selected === i
                    ? 'bg-accentdim'
                    : 'hover:bg-panel2'}`}>
                <td className={`${TD} font-mono text-[12px] text-ink3`}>{i + 1}</td>
                <td className={TD}>
                  <strong className="font-[650]">{h.name}</strong>
                  {h.why_cut && <div className="text-[12px] text-ink2">{h.why_cut}</div>}
                  {/* The reason a step is NOT a cut is the other half of
                      mitigate-vs-additional, and it lived in the content
                      file unrendered until now. Muted below why_cut: it is
                      context for the step, not an instruction. */}
                  {h.note && <div className="text-[12px] text-ink3">{h.note}</div>}
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
 * HAND-WRITTEN SVG, still. This is the only diagram in the product and it is a
 * row of boxes and arrows; a graph library would be the largest thing in the
 * bundle by an order of magnitude, and the dependency budget is a product
 * argument here, not a preference.
 *
 * THE THREE VISUAL STATES CARRY MEANING, and each is now said twice — once in
 * colour and once in movement — because the first version said them once, in a
 * dash pattern, and a dash pattern is easy to miss at a glance:
 *
 *   holds        solid stroke, filled box, connector FLOWS
 *   not present  dashed stroke, hollow box, connector STILL
 *   a cut        crit colour, pulsing ring, ribbon above the box
 *
 * A viewer who reads dashed as "less important" rather than "not currently true"
 * would misread the whole diagram, which is why the legend states it in words as
 * well. Motion is not load-bearing on its own: switch it off for reduced motion
 * and the colour and the dash still carry every distinction.
 *
 * THE ROUTE NOW ENDS SOMEWHERE. It used to stop at the last condition, which
 * quietly undercut the product's own claim that a path terminates in a currency
 * figure rather than a severity word. The terminal node is that figure.
 */

const PITCH = 202
const BOX_W = 166
const BOX_H = 84
const BOX_Y = 34
const MID = BOX_Y + BOX_H / 2
const END_W = 158

/**
 * Word-aware wrapping for SVG `<text>`, which does not wrap on its own.
 *
 * REPLACES `name.slice(0, 24)` + `name.slice(24, 46)`. That broke the label
 * wherever the 24th character happened to land — the shipped screen read
 * "Unauthenticated entry po / int exposed" and "OS command execution rea /
 * chable" — and silently dropped everything past the 46th with nothing to say it
 * had. A label that lies about its own content is worse than a short one.
 *
 * A word is only ever split when the word ALONE cannot fit a line, which is the
 * one case where leaving it whole would overflow the box.
 */
export function wrapWords(text: string, perLine: number, maxLines: number): string[] {
  const words = text.split(/\s+/).filter(Boolean)
  const lines: string[] = []
  let line = ''
  let i = 0
  for (; i < words.length; i++) {
    const w = words[i]
    const candidate = line ? `${line} ${w}` : w
    if (candidate.length <= perLine) { line = candidate; continue }
    if (line) { lines.push(line); line = '' }
    if (lines.length >= maxLines) break
    line = w.length > perLine ? w.slice(0, perLine) : w
  }
  let dropped = i < words.length
  if (line) {
    if (lines.length < maxLines) lines.push(line)
    else dropped = true
  }
  if (dropped && lines.length > 0) {
    const last = lines.length - 1
    lines[last] = lines[last].slice(0, Math.max(1, perLine - 1)).trimEnd() + '…'
  }
  return lines
}

function RouteDiagram({ hops, scenario, ale, selected, onSelect }: {
  hops: PathHop[]
  scenario: string | null
  ale: number | null
  selected: number | null
  // Only ever called with a real index; clearing is the parent toggling it back.
  onSelect: (i: number) => void
}) {
  // Hover previews, selection persists. Hover wins while the cursor is on a node
  // so the diagram answers immediately, and falls back to the selection when it
  // leaves rather than blanking — a detail panel that empties on mouse-out makes
  // the reader chase it.
  const [hovered, setHovered] = useState<number | null>(null)
  const active = hovered ?? selected
  const width = 30 + hops.length * PITCH + END_W + 30
  const detail = active !== null ? hops[active] : null

  return (
    <div className="rounded-lg border border-line bg-panel p-4">
      <div className="overflow-x-auto">
        <svg viewBox={`0 0 ${width} 132`} width="100%"
             style={{ maxWidth: `${width}px`, minWidth: '560px' }}
             role="img" aria-label="Risk path diagram">
          <defs>
            <marker id="rp-ar" markerWidth="9" markerHeight="7" refX="9" refY="3.5" orient="auto">
              <polygon points="0 0, 9 3.5, 0 7" fill="var(--ink-faint)" />
            </marker>
            <marker id="rp-ar-live" markerWidth="9" markerHeight="7" refX="9" refY="3.5" orient="auto">
              <polygon points="0 0, 9 3.5, 0 7" fill="var(--accent)" />
            </marker>
          </defs>

          {/* Where the route starts. Without it the first box reads as though it
              followed something off-screen. */}
          <circle cx={16} cy={MID} r={4.5} fill="var(--accent)" />
          <line x1={20} y1={MID} x2={22} y2={MID} stroke="var(--accent)" strokeWidth={1.5} />

          {hops.map((h, i) => {
            const x = 30 + i * PITCH
            const cut = h.is_cut && h.present
            const dim = active !== null && active !== i
            const lines = wrapWords(h.name, 24, 3)
            // The connector INTO this step is live when this condition holds and
            // the one before it does. Movement therefore stops at the first step
            // that is not present, which is exactly where the route stops.
            const live = h.present && (i === 0 || hops[i - 1].present)
            return (
              <g key={`${i}-${h.name}`}
                 className={`rp-step rp-node${dim ? ' rp-dim' : ''}`}
                 style={{ animationDelay: `${i * 70}ms` }}
                 tabIndex={0}
                 role="button"
                 aria-pressed={selected === i}
                 aria-label={
                   `Step ${i + 1} of ${hops.length}: ${h.name}. ` +
                   `${h.required ? 'Required' : 'Contributing'}. ` +
                   `${cut ? 'This is a cut: closing it severs the path. ' : ''}` +
                   `${h.present ? `${h.evidence_total} finding(s).` : 'Not present.'}`
                 }
                 onMouseEnter={() => setHovered(i)}
                 onMouseLeave={() => setHovered(null)}
                 onFocus={() => setHovered(i)}
                 onBlur={() => setHovered(null)}
                 onClick={() => onSelect(i)}
                 onKeyDown={(e) => {
                   if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelect(i) }
                 }}>

                {i > 0 && (
                  <line x1={x - 36} y1={MID} x2={x - 8} y2={MID}
                        className={live ? 'rp-flow' : undefined}
                        stroke={live ? 'var(--accent)' : 'var(--ink-faint)'}
                        strokeWidth={live ? 2 : 1.5}
                        strokeDasharray={live ? undefined : '4 3'}
                        markerEnd={`url(#${live ? 'rp-ar-live' : 'rp-ar'})`} />
                )}
                {i === 0 && (
                  <line x1={22} y1={MID} x2={x - 8} y2={MID}
                        className={live ? 'rp-flow' : undefined}
                        stroke={live ? 'var(--accent)' : 'var(--ink-faint)'}
                        strokeWidth={live ? 2 : 1.5}
                        strokeDasharray={live ? undefined : '4 3'}
                        markerEnd={`url(#${live ? 'rp-ar-live' : 'rp-ar'})`} />
                )}

                {/* The pulse sits BEHIND the box and is the only thing on the
                    screen asking for attention, because it is the only thing a
                    reader can close to end the path. */}
                {cut && (
                  <rect className="rp-pulse" x={x - 3} y={BOX_Y - 3}
                        width={BOX_W + 6} height={BOX_H + 6} rx={12}
                        fill="none" stroke="var(--crit)" strokeWidth={2} />
                )}

                {/* Selection ring, distinct from the cut ring: accent, and it does
                    not pulse, because "you are looking at this" is not urgent. */}
                {selected === i && (
                  <rect className="rp-halo" x={x - 5} y={BOX_Y - 5}
                        width={BOX_W + 10} height={BOX_H + 10} rx={14}
                        fill="none" stroke="var(--accent)" strokeWidth={1.5} />
                )}

                <rect x={x} y={BOX_Y} width={BOX_W} height={BOX_H} rx={10}
                      fill={cut ? 'rgba(244,63,94,.13)'
                                : h.present ? 'var(--panel-2)' : 'transparent'}
                      stroke={cut ? 'var(--crit)' : h.present ? 'var(--line)' : 'var(--ink-faint)'}
                      strokeWidth={cut ? 2 : 1}
                      strokeDasharray={h.present ? undefined : '4 3'} />

                <circle cx={x + 17} cy={BOX_Y + 17} r={9}
                        fill={cut ? 'var(--crit)' : h.present ? 'var(--accent)' : 'transparent'}
                        stroke={h.present || cut ? 'none' : 'var(--ink-faint)'} strokeWidth={1} />
                <text x={x + 17} y={BOX_Y + 20.5} fontSize={9.5} fontWeight={700}
                      textAnchor="middle"
                      fill={h.present || cut ? '#fff' : 'var(--ink-faint)'}>{i + 1}</text>

                <text x={x + 32} y={BOX_Y + 21} fontSize={8.5} fontWeight={600}
                      letterSpacing=".06em" fill="var(--ink-faint)">
                  {h.required ? 'REQUIRED' : 'CONTRIBUTING'}
                </text>

                <text x={x + 13} fontSize={10.5} fill="var(--ink)">
                  {lines.map((ln, k) => (
                    <tspan key={k} x={x + 13} y={BOX_Y + 42 + k * 12.5}>{ln}</tspan>
                  ))}
                </text>

                <text x={x + 13} y={BOX_Y + BOX_H - 9} fontSize={9}
                      fill={h.present ? 'var(--ink-dim)' : 'var(--ink-faint)'}>
                  {h.present ? `${h.evidence_total} finding(s)` : 'not present'}
                </text>

                {cut && (
                  <text x={x} y={24} fontSize={9} fontWeight={700} fill="var(--crit)">
                    CUT &#8212; closing this severs the path
                  </text>
                )}
              </g>
            )
          })}

          {/* The terminus. A path ends at a LOSS SCENARIO rather than a severity
              word, and that is the sentence no incumbent's report produces — so it
              belongs on the drawing, not only in the header line.

              THE SCENARIO IS THE HEADLINE HERE, NOT THE MONEY, and that is a
              deliberate retreat from the first draft of this node. `PathView`
              carries no `loss_model`, so this screen cannot ask lib/pricing
              whether the figure is the customer's own or the shipped catalogue's
              illustrative $1bn manufacturer — and printing the latter under a
              customer's name is the exact defect pricing.ts was written to end.
              The header line has always shown it behind a null check, so showing
              it at body weight is parity; setting it 15px bold as the visual
              payoff of the whole diagram would have been an unverifiable number
              wearing the most authoritative typography on the screen.

              The fix is upstream: put `loss_model` on the path payload and gate
              this the way Risk.tsx and Dashboard.tsx already do. */}
          {(() => {
            const xe = 30 + hops.length * PITCH
            const reached = hops.every((h) => !h.required || h.present)
            return (
              <g>
                <line x1={xe - 36} y1={MID} x2={xe - 8} y2={MID}
                      className={reached ? 'rp-flow' : undefined}
                      stroke={reached ? 'var(--crit)' : 'var(--ink-faint)'}
                      strokeWidth={reached ? 2 : 1.5}
                      strokeDasharray={reached ? undefined : '4 3'}
                      markerEnd={`url(#${reached ? 'rp-ar' : 'rp-ar'})`} />
                <rect x={xe} y={BOX_Y} width={END_W} height={BOX_H} rx={10}
                      fill="rgba(244,63,94,.09)" stroke="var(--crit)"
                      strokeWidth={1} strokeDasharray="5 4" />
                <text x={xe + 14} y={BOX_Y + 20} fontSize={8.5} fontWeight={600}
                      letterSpacing=".06em" fill="var(--crit)">ENDS AT</text>
                <text x={xe + 14} y={BOX_Y + 41} fontSize={12.5} fontWeight={600}
                      fill="var(--ink)" fontFamily="var(--font-mono)">
                  {scenario ?? '—'}
                </text>
                <text x={xe + 14} y={BOX_Y + 59} fontSize={10.5} fill="var(--ink-dim)">
                  {ale ? `exposure ${money(ale)}` : 'not quantified'}
                </text>
                <text x={xe + 14} y={BOX_Y + BOX_H - 9} fontSize={8.5} fill="var(--ink-faint)">
                  {ale ? 'annualised, P90' : 'no figures supplied'}
                </text>
              </g>
            )
          })()}
        </svg>
      </div>

      {/* The full label, which the boxes cannot hold. Fixed minimum height so
          moving between steps does not shift the page under the cursor. */}
      <div className="mt-3 rounded-md border border-line bg-panel2 px-3.5 py-2.5 min-h-[72px]">
        {detail === null ? (
          <p className="text-[12px] text-ink3">
            Hover a step to read it in full, or select one to keep it and highlight
            its row in the table below.
          </p>
        ) : (
          <>
            <div className="flex items-baseline gap-2 flex-wrap">
              <span className="font-mono text-[11px] text-ink3">
                Step {(active ?? 0) + 1}/{hops.length}
              </span>
              <strong className="font-[650] text-[13px]">{detail.name}</strong>
              {detail.is_cut && detail.present && (
                <span className="pill sev-CRITICAL">cut</span>
              )}
              {!detail.present && (
                <span className="text-[11px] text-ink3">not present</span>
              )}
            </div>
            {detail.why_cut && (
              <p className="text-[12px] text-ink2 mt-1">{detail.why_cut}</p>
            )}
            {detail.note && (
              <p className="text-[12px] text-ink3 mt-1">{detail.note}</p>
            )}
            {detail.checks.length > 0 && (
              <p className="text-[11px] text-ink3 font-mono mt-1.5">
                {detail.checks.join(' · ')}
              </p>
            )}
          </>
        )}
      </div>

      <div className="mt-2.5 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-ink3">
        <span className="inline-flex items-center gap-1.5">
          <svg width="22" height="8" aria-hidden="true">
            <line x1="0" y1="4" x2="22" y2="4" stroke="var(--accent)" strokeWidth="2" />
          </svg>
          the condition holds, and the route runs through it
        </span>
        <span className="inline-flex items-center gap-1.5">
          <svg width="22" height="8" aria-hidden="true">
            <line x1="0" y1="4" x2="22" y2="4" stroke="var(--ink-faint)"
                  strokeWidth="1.5" strokeDasharray="4 3" />
          </svg>
          not present &#8212; not "less important"
        </span>
        <span className="inline-flex items-center gap-1.5">
          <svg width="14" height="10" aria-hidden="true">
            <rect x="1" y="1" width="12" height="8" rx="2.5" fill="none"
                  stroke="var(--crit)" strokeWidth="2" />
          </svg>
          a cut &#8212; closing it severs the path
        </span>
      </div>
    </div>
  )
}
