import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router'
import { ApiError, path as fetchPath } from '../api/client'
import type {
  PathActors, PathFinding, PathHop, PathView, RemediationOwner,
} from '../api/types'
import { useTitle } from '../lib/title'
import { money } from './Risk'
import { isPriced } from '../lib/pricing'
import { CheckRefs } from '../components/Refs'
import { Waypoints } from 'lucide-react'
import { CARD_TITLE as CARD_H3 } from '../lib/ui'

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

const CARD = 'rounded-lg border border-cardline bg-panel p-4'
const G2 = 'grid gap-3.5 [grid-template-columns:repeat(auto-fit,minmax(340px,1fr))]'
const H2 = 'text-[15px] font-semibold text-ink mt-7 mb-2.5'
const TH = 'text-left text-[11px] font-semibold uppercase tracking-[.05em] text-ink3 px-2.5 py-2 border-b border-line'
const TD = 'px-2.5 py-2.5 border-b border-line align-top'
const TABLE_CARD = 'rounded-lg border border-cardline bg-panel overflow-x-auto'
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
        <Link className={LINK} to="/paths">&larr; Risk Paths</Link>
      </p>
      {failure && <div className="banner banner-bad">{failure}</div>}
      {!failure && view === null && <p className="text-[13px] text-ink3">Loading…</p>}
      {view !== null && <Body view={view} />}
    </>
  )
}

/**
 * Who the configuration puts on this path.
 *
 * The hops name the CHECKS that evidence them and never the accounts, so this
 * is the one thing on the screen that the path templates cannot produce — it
 * comes from the attack graph, by walking one privilege edge back from the
 * objects the path's findings name.
 *
 * THE WORDING IS THE FEATURE. An edge is derived from configuration, so this
 * says these accounts HOLD the privileges the route depends on, never that any
 * of them used it. `used` on an edge means only that the account logged on in
 * the exported window, which evidences the account is live — so it is rendered
 * as "signed in recently" and not as anything about this path.
 *
 * An empty list is two different things and they must not draw alike: a path
 * whose objects no edge reaches says nothing about the estate, while a path the
 * graph does reach and finds nobody on is a real answer. `reachable_objects`
 * separates them.
 */
function ActorsSection({ actors }: { actors?: PathActors }) {
  if (!actors) return null
  const { actors: rows, reachable_objects, objects_on_path, edges_available } = actors

  if (rows.length === 0) {
    return (
      <>
        <h2 className={H2}>Who holds these privileges</h2>
        <p className="text-[13px] text-ink2 mb-4">
          {edges_available === 0
            ? 'No relationships have been derived for this landscape yet, so nobody can be named either way.'
            : reachable_objects === 0
              ? 'The graph reaches none of the objects on this path, so this is not an answer about who can take it — it is the absence of one.'
              : 'No account holds a privilege the graph connects to this path.'}
        </p>
      </>
    )
  }

  return (
    <>
      <h2 className={H2}>Who holds these privileges</h2>
      <p className="text-[12px] text-ink3 mb-2.5">
        Held by configuration, not observed in use: an edge records what the
        export says is granted, never that this route was taken.
        {typeof objects_on_path === 'number' && (
          <> The graph reaches {reachable_objects} of the {objects_on_path}{' '}
            object{objects_on_path === 1 ? '' : 's'} on this path.</>
        )}
      </p>
      <div className={TABLE_CARD}>
        <table className="w-full border-collapse">
          <thead>
            <tr>
              <th className={`${TH} w-[180px]`}>Account</th>
              <th className={TH}>Holds</th>
              <th className={`${TH} w-[150px]`}>Account activity</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((a) => (
              <tr key={a.actor} className="hover:bg-panel2">
                <td className={`${TD} font-mono`}>{a.actor}</td>
                <td className={TD}>
                  {a.via.map((v, i) => (
                    <span key={`${v.object}-${v.edge_type}-${i}`}
                          className="block text-[12px]">
                      <span className="text-ink3">{v.edge_type.replace(/_/g, ' ')}</span>{' '}
                      <span className="font-mono">{v.object}</span>
                    </span>
                  ))}
                </td>
                <td className={`${TD} text-[12px] text-ink2`}>
                  {a.any_used
                    ? 'signed in during the exported window'
                    : 'no logon evidence either way'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
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
  // The figure is shown only when the model says it came from the customer's own
  // answers. Unknown counts as unpriced, which is lib/pricing's whole point.
  const priced = isPriced({ loss_model: path.loss_model })
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
        {priced && path.scenario_ale
          ? ` · exposure ${money(path.scenario_ale)}` : ''}
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
      <RouteDiagram hops={hops} scenario={path.fair_scenario}
                    ale={priced ? path.scenario_ale : null}
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
                  <div className="text-[12px]"><CheckRefs ids={h.checks} /></div>
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

      <ActorsSection actors={view.actors} />

      <h2 className={H2}>All evidence</h2>
      <div className={TABLE_CARD} data-evidence>
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
/*
 * GEOMETRY, AND WHY IT GREW.
 *
 * The first version of this diagram was hard to read at arm's length, for two
 * reasons that look like one. Raising the font sizes alone would have fixed
 * half of it.
 *
 *   1. The type was small in viewBox units: 10.5 for a step label, 8.5 for the
 *      REQUIRED tag.
 *   2. The svg was `width="100%"` with `maxWidth: {width}px`, so a six-hop path
 *      -- about 1430 units wide -- was SCALED DOWN to whatever the container
 *      gave it. In a 1000px column that is 0.7, and a 10.5px label lands on
 *      screen at about 7px. The diagram got smaller the more it had to say,
 *      which is precisely backwards.
 *
 * So the type roughly doubled AND the svg now renders at its natural size and
 * scrolls horizontally instead of shrinking. The trade is real and deliberate:
 * a six-hop path no longer fits a 1000px column in one screenful. Legibility
 * wins, because a diagram nobody can read at a glance is not serving anyone,
 * and the card was already an `overflow-x-auto` scroller.
 */
const PITCH = 284
const BOX_W = 240
const BOX_H = 128
const BOX_Y = 34
const MID = BOX_Y + BOX_H / 2
const END_W = 210
const HEIGHT = 180
/* Left margin before the FIRST box, and the reason it is not 30.
   The entry arrow has to fit between the start dot and box one. At 30 there was
   no room for it: the connector ran from 26 to (30 - 11) = 19, which is
   right-to-left, so `orient="auto"` faced the arrowhead BACKWARDS into the dot
   and drew it over the box it was supposed to point at. A reversed arrow on a
   diagram whose whole subject is direction is not a cosmetic defect. */
const LEFT = 88

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

/**
 * The route, drawn.
 *
 * HAND-WRITTEN SVG, still. This is the only diagram in the product and it is a
 * row of boxes and arrows; a graph library would be the largest thing in the
 * bundle by an order of magnitude, and the dependency budget is a product
 * argument here, not a preference.
 *
 * THE THREE VISUAL STATES CARRY MEANING, and each is said twice — once in
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
 * THE ROUTE ENDS SOMEWHERE. It used to stop at the last condition, which quietly
 * undercut the product's own claim that a path terminates in a loss scenario
 * rather than a severity word.
 */
function RouteDiagram({ hops, scenario, ale, selected, onSelect }: {
  hops: PathHop[]
  scenario: string | null
  ale: number | null
  // Only ever called with a real index; clearing is the parent toggling it back.
  onSelect: (i: number) => void
  selected: number | null
}) {
  // Hover previews, selection persists. Hover wins while the cursor is on a node
  // so the diagram answers immediately, and falls back to the selection when it
  // leaves rather than blanking — a detail panel that empties on mouse-out makes
  // the reader chase it.
  const [hovered, setHovered] = useState<number | null>(null)
  const active = hovered ?? selected
  const width = LEFT + hops.length * PITCH + END_W + 30
  const detail = active !== null ? hops[active] : null

  return (
    <div className="rounded-lg border border-cardline bg-panel p-4">
      <div className="overflow-x-auto">
        {/* Natural size, NOT width="100%". See the note on the constants above:
            scaling to the container made a long path render small, so the
            diagram got harder to read the more steps it had. */}
        <svg viewBox={`0 0 ${width} ${HEIGHT}`} width={width} height={HEIGHT}
             style={{ display: 'block' }}
             role="img" aria-label="Risk path diagram">
          <defs>
{/* markerUnits="userSpaceOnUse" is load-bearing. The DEFAULT is
                "strokeWidth", which multiplies the marker by the stroke it sits
                on — so when the resize took connectors from 1.5 to 3, every
                arrowhead silently went from 9 units wide to 27 and swallowed the
                edge of the box. A fixed head keeps the two weights of connector
                (live and still) wearing the same arrow, which is what makes them
                comparable at a glance. refX = markerWidth puts the TIP on the
                line's end point, so the endpoint is where the arrow lands. */}
            <marker id="rp-ar" markerUnits="userSpaceOnUse"
                    markerWidth="13" markerHeight="10" refX="13" refY="5" orient="auto">
              <polygon points="0 0, 13 5, 0 10" fill="var(--ink-faint)" />
            </marker>
            <marker id="rp-ar-live" markerUnits="userSpaceOnUse"
                    markerWidth="13" markerHeight="10" refX="13" refY="5" orient="auto">
              <polygon points="0 0, 13 5, 0 10" fill="var(--accent)" />
            </marker>
          </defs>

          {/* Where the route starts. Without it the first box reads as though it
              followed something off-screen. */}
          <circle cx={22} cy={MID} r={7} fill="var(--accent)" />

          {hops.map((h, i) => {
            const x = LEFT + i * PITCH
            const cut = h.is_cut && h.present
            const dim = active !== null && active !== i
            const lines = wrapWords(h.name, 23, 3)
            // The connector INTO this step is live when this condition holds and
            // the one before it does. Movement therefore stops at the first step
            // that is not present, which is exactly where the route stops.
            const live = h.present && (i === 0 || hops[i - 1].present)
            // Start just clear of the entry dot for step one, and just clear
            // of the previous box for every other step. Both END at the same
            // offset from the box they point at, so the arrows line up.
            const from = i === 0 ? 33 : x - PITCH + BOX_W + 6
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

                <line x1={from} y1={MID} x2={x - 4} y2={MID}
                      className={live ? 'rp-flow' : undefined}
                      stroke={live ? 'var(--accent)' : 'var(--ink-faint)'}
                      strokeWidth={live ? 3 : 2}
                      strokeDasharray={live ? undefined : '5 4'}
                      markerEnd={`url(#${live ? 'rp-ar-live' : 'rp-ar'})`} />

                {/* The pulse sits BEHIND the box and is the only thing on the
                    screen asking for attention, because it is the only thing a
                    reader can close to end the path. */}
                {cut && (
                  <rect className="rp-pulse" x={x - 4} y={BOX_Y - 4}
                        width={BOX_W + 8} height={BOX_H + 8} rx={16}
                        fill="none" stroke="var(--crit)" strokeWidth={2.5} />
                )}

                {/* Selection ring, distinct from the cut ring: accent, and it does
                    not pulse, because "you are looking at this" is not urgent. */}
                {selected === i && (
                  <rect className="rp-halo" x={x - 8} y={BOX_Y - 8}
                        width={BOX_W + 16} height={BOX_H + 16} rx={19}
                        fill="none" stroke="var(--accent)" strokeWidth={2} />
                )}

                <rect x={x} y={BOX_Y} width={BOX_W} height={BOX_H} rx={13}
                      fill={cut ? 'rgba(244,63,94,.13)'
                                : h.present ? 'var(--panel-2)' : 'transparent'}
                      stroke={cut ? 'var(--crit)' : h.present ? 'var(--line)' : 'var(--ink-faint)'}
                      strokeWidth={cut ? 2.5 : 1.25}
                      strokeDasharray={h.present ? undefined : '5 4'} />

                <circle cx={x + 24} cy={BOX_Y + 25} r={13}
                        fill={cut ? 'var(--crit)' : h.present ? 'var(--accent)' : 'transparent'}
                        stroke={h.present || cut ? 'none' : 'var(--ink-faint)'} strokeWidth={1.25} />
                <text x={x + 24} y={BOX_Y + 30} fontSize={14} fontWeight={700}
                      textAnchor="middle"
                      fill={h.present || cut ? '#fff' : 'var(--ink-faint)'}>{i + 1}</text>

                <text x={x + 46} y={BOX_Y + 30} fontSize={11.5} fontWeight={700}
                      letterSpacing=".07em" fill="var(--ink-faint)">
                  {h.required ? 'REQUIRED' : 'CONTRIBUTING'}
                </text>

                <text x={x + 18} fontSize={15} fill="var(--ink)">
                  {lines.map((ln, k) => (
                    <tspan key={k} x={x + 18} y={BOX_Y + 58 + k * 18}>{ln}</tspan>
                  ))}
                </text>

                <text x={x + 18} y={BOX_Y + BOX_H - 14} fontSize={12.5}
                      fill={h.present ? 'var(--ink-dim)' : 'var(--ink-faint)'}>
                  {h.present ? `${h.evidence_total} finding(s)` : 'not present'}
                </text>

                {cut && (
                  <text x={x} y={23} fontSize={12} fontWeight={700} fill="var(--crit)">
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
              it at body weight is parity; setting it as the visual payoff of the
              whole diagram would have been an unverifiable number wearing the
              most authoritative typography on the screen.

              The fix is upstream: put `loss_model` on the path payload and gate
              this the way Risk.tsx and Dashboard.tsx already do. */}
          {(() => {
            const xe = LEFT + hops.length * PITCH
            const reached = hops.every((h) => !h.required || h.present)
            return (
              <g>
                <line x1={xe - PITCH + BOX_W + 6} y1={MID} x2={xe - 4} y2={MID}
                      className={reached ? 'rp-flow' : undefined}
                      stroke={reached ? 'var(--crit)' : 'var(--ink-faint)'}
                      strokeWidth={reached ? 3 : 2}
                      strokeDasharray={reached ? undefined : '5 4'}
                      markerEnd="url(#rp-ar)" />
                <rect x={xe} y={BOX_Y} width={END_W} height={BOX_H} rx={13}
                      fill="rgba(244,63,94,.09)" stroke="var(--crit)"
                      strokeWidth={1.5} strokeDasharray="6 5" />
                <text x={xe + 20} y={BOX_Y + 30} fontSize={11.5} fontWeight={700}
                      letterSpacing=".07em" fill="var(--crit)">ENDS AT</text>
                <text x={xe + 20} y={BOX_Y + 62} fontSize={18} fontWeight={700}
                      fill="var(--ink)" fontFamily="var(--font-mono)">
                  {scenario ?? '—'}
                </text>
                <text x={xe + 20} y={BOX_Y + 88} fontSize={14} fill="var(--ink-dim)">
                  {ale ? `exposure ${money(ale)}` : 'not quantified'}
                </text>
                <text x={xe + 20} y={BOX_Y + BOX_H - 14} fontSize={11.5} fill="var(--ink-faint)">
                  {ale ? 'annualised, P90' : 'no figures supplied'}
                </text>
              </g>
            )
          })()}
        </svg>
      </div>

      {/* The full label, which the boxes cannot hold. Fixed minimum height so
          moving between steps does not shift the page under the cursor. */}
      <div className="mt-3 rounded-md border border-cardline bg-panel2 px-4 py-3 min-h-[84px]">
        {detail === null ? (
          <p className="text-[13.5px] text-ink3">
            Hover a step to read it in full, or select one to keep it and highlight
            its row in the table below.
          </p>
        ) : (
          <>
            <div className="flex items-baseline gap-2.5 flex-wrap">
              <span className="font-mono text-[12.5px] text-ink3">
                Step {(active ?? 0) + 1}/{hops.length}
              </span>
              <strong className="font-[650] text-[15px]">{detail.name}</strong>
              {detail.is_cut && detail.present && (
                <span className="pill sev-CRITICAL">cut</span>
              )}
              {!detail.present && (
                <span className="text-[12.5px] text-ink3">not present</span>
              )}
            </div>
            {detail.why_cut && (
              <p className="text-[13.5px] text-ink2 mt-1.5">{detail.why_cut}</p>
            )}
            {detail.note && (
              <p className="text-[13.5px] text-ink3 mt-1.5">{detail.note}</p>
            )}
            {detail.checks.length > 0 && (
              <p className="text-[12.5px] mt-2">
                <CheckRefs ids={detail.checks} />
              </p>
            )}
          </>
        )}
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-x-5 gap-y-1.5 text-[12.5px] text-ink3">
        <span className="inline-flex items-center gap-2">
          <svg width="26" height="10" aria-hidden="true">
            <line x1="0" y1="5" x2="26" y2="5" stroke="var(--accent)" strokeWidth="3" />
          </svg>
          the condition holds, and the route runs through it
        </span>
        <span className="inline-flex items-center gap-2">
          <svg width="26" height="10" aria-hidden="true">
            <line x1="0" y1="5" x2="26" y2="5" stroke="var(--ink-faint)"
                  strokeWidth="2" strokeDasharray="5 4" />
          </svg>
          not present &#8212; not "less important"
        </span>
        <span className="inline-flex items-center gap-2">
          <svg width="17" height="12" aria-hidden="true">
            <rect x="1.5" y="1.5" width="14" height="9" rx="3" fill="none"
                  stroke="var(--crit)" strokeWidth="2.5" />
          </svg>
          a cut &#8212; closing it severs the path
        </span>
      </div>
    </div>
  )
}
