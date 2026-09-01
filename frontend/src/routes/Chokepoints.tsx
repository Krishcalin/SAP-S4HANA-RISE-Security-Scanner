import { useEffect, useState } from 'react'
import { Link } from 'react-router'
import { ApiError, chokepoints as fetchChokepoints,
         severingSets as fetchSeveringSets } from '../api/client'
import type { ChokepointsView, RemediationOwner, SeveringSet } from '../api/types'
import { useTitle } from '../lib/title'
import { Scissors } from 'lucide-react'
import { CARD_TITLE as CARD_H3, KPI, KPI_NOTE } from '../lib/ui'
import { money } from './Risk'
import { UNPRICED_CELL } from '../lib/pricing'

/**
 * The shortest worklist this product can produce.
 *
 * A choke point is a finding sitting on a CUT hop: closing it severs every path
 * it appears on. That converts a 300-row findings queue into a handful of lines
 * with a stated consequence each — "close this and four paths die" — which is a
 * far more persuasive artefact than any picture of a graph.
 *
 * WHY IT IS ITS OWN SCREEN. The paths page already showed these, capped at
 * fifteen, beside the path list. That is the right treatment for a summary and
 * the wrong one for a worklist: a cap that exists to keep another screen legible
 * silently decides how much work a reader is shown. Here the list is the page,
 * so it is uncapped in practice and says so when it is not.
 *
 * ONLY CUT HOPS COUNT, which is the whole discipline of the screen. A finding on
 * a non-cut hop reduces exploitability without severing anything; including it
 * would promise a closure this page cannot deliver, and one line that does not
 * do what the column header says is enough to make a reader distrust the other
 * forty.
 *
 * RANKED BY CONSEQUENCE, NOT BY SEVERITY. A MEDIUM that severs three paths is
 * above a CRITICAL that severs one, because the question this screen answers is
 * "what should I do first", not "what is worst". The severity is still on the
 * row; it is just not the sort key.
 */

const CARD = 'rounded-lg border border-cardline bg-panel p-4'
const G4 = 'grid gap-3.5 [grid-template-columns:repeat(auto-fit,minmax(210px,1fr))]'
const H2 = 'text-[15px] font-semibold text-ink mt-7 mb-2.5'
const TH = 'text-left text-[11px] font-semibold uppercase tracking-[.05em] text-ink3 px-2.5 py-2 border-b border-line'
const TD = 'px-2.5 py-2.5 border-b border-line align-top'
const TABLE_CARD = 'rounded-lg border border-cardline bg-panel overflow-x-auto'
const LINK = 'text-accent hover:underline'

const OWNER_SHORT: Record<RemediationOwner, string> = {
  customer_fixable: 'yours',
  ticket_to_sap: 'SAP',
  provider_owned: "SAP's",
  not_assessable: 'out of reach',
}

export function Chokepoints() {
  const [view, setView] = useState<ChokepointsView | null>(null)
  const [failure, setFailure] = useState<string | null>(null)

  useTitle('Choke Points')

  const [plans, setPlans] = useState<SeveringSet[] | null>(null)

  useEffect(() => {
    let live = true
    // A separate, non-blocking fetch. The worklist is this page's job; the
    // plans are the answer to the question the worklist raises, and a page
    // that failed entirely because the second one did would be worse at the
    // first one.
    fetchSeveringSets()
      .then((v) => { if (live) setPlans(v.scenarios) })
      .catch(() => { if (live) setPlans([]) })
    fetchChokepoints()
      .then((v) => { if (live) setView(v) })
      .catch((e: unknown) => {
        if (!live) return
        const status = e instanceof ApiError ? e.status : 0
        setFailure(status === 403
          ? 'Your account is not permitted to see the risk-path model.'
          : `The choke points could not be loaded${status ? ` (HTTP ${status})` : ''}.`)
      })
    return () => { live = false }
  }, [])

  return (
    <>
      <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2 mb-1">
        <Scissors size={22} className="text-accent shrink-0" />
        Choke Points
      </h1>
      <p className="text-ink2 mb-5">
        One fix, one or more paths gone. Ranked by how many they sever.
      </p>

      {failure && <div className="banner banner-bad">{failure}</div>}
      {!failure && view === null && <p className="text-[13px] text-ink3">Loading…</p>}
      {plans !== null && plans.length > 0 && <Plans plans={plans} />}
      {view !== null && <Body view={view} />}
    </>
  )
}

/**
 * What it takes to close each scenario outright.
 *
 * WHY THIS SITS ABOVE THE WORKLIST. A choke point carries a figure only where
 * closing it ALONE severs every route, and on a real estate that almost never
 * happens — the reference landscape has four to six independent routes to each
 * scenario, so every row below shows a dash in the Worth column. Without this
 * panel the reader's honest conclusion is that the money does not work.
 *
 * It answers the question that has an answer: not "which single fix closes
 * this" but "which fixes, together" — and that is what somebody schedules.
 */
function Plans({ plans }: { plans: SeveringSet[] }) {
  return (
    <>
      <h2 className={H2}>What it takes to close a scenario outright</h2>
      <div className="grid gap-3 [grid-template-columns:repeat(auto-fit,minmax(320px,1fr))]">
        {plans.map((p) => (
          <div key={p.scenario} className={CARD}>
            <div className="flex items-baseline justify-between gap-3">
              <span className="font-semibold text-ink">{p.scenario}</span>
              <span className="font-mono text-[13px] text-ink">
                {p.ale_mean ? money(p.ale_mean) : UNPRICED_CELL}
              </span>
            </div>
            {p.closable ? (
              <>
                <p className="text-[12px] text-ink3 mt-1 mb-2">
                  {p.fixes.length === 1
                    ? 'One fix closes '
                    : `${p.fixes.length} fixes close `}
                  {p.paths_open === 1 ? 'its only route' : `all ${p.paths_open} routes`}
                </p>
                <ul className="text-[12px] space-y-1">
                  {p.fixes.map((f) => (
                    <li key={f.finding_id} className="flex items-baseline gap-2">
                      <span className={`pill sev-${f.severity ?? 'INFO'} shrink-0`}>
                        {f.severity}
                      </span>
                      <Link className={`${LINK} font-mono shrink-0`}
                            to={`/findings/${f.finding_id}`}>{f.check_id}</Link>
                      <span className="text-ink3 truncate">{f.title}</span>
                    </li>
                  ))}
                </ul>
              </>
            ) : (
              /* Not a plan with a caveat. A route no fix can sever means no set
                 of fixes closes this, and offering one that ignored it would be
                 a false all-clear. */
              <p className="text-[12px] text-ink3 mt-1">
                No set of fixes closes this: {p.reason}
              </p>
            )}
          </div>
        ))}
      </div>
    </>
  )
}

function Body({ view }: { view: ChokepointsView }) {
  const { chokepoints: rows, summary } = view

  return (
    <>
      <div className={G4}>
        <div className={CARD}>
          <h3 className={CARD_H3}>Choke points</h3>
          <div className={KPI}>{summary.total}</div>
          <div className={KPI_NOTE}>single fixes that sever a path</div>
        </div>
        <div className={CARD}>
          <h3 className={CARD_H3}>Sever more than one</h3>
          <div className={`${KPI} text-crit`}>{summary.multi_path}</div>
          <div className={KPI_NOTE}>do these first</div>
        </div>
        <div className={CARD}>
          <h3 className={CARD_H3}>Yours to fix</h3>
          <div className={`${KPI} text-ok`}>{summary.customer_fixable}</div>
          <div className={KPI_NOTE}>
            no service request needed
          </div>
        </div>
        <div className={CARD}>
          <h3 className={CARD_H3}>Open paths</h3>
          <div className={KPI}>{summary.open_paths}</div>
          <div className={KPI_NOTE}>
            {/* NOT the sum of the Severs column: most paths have more than one
                cut, so adding that column up counts them repeatedly. */}
            what there is to sever
          </div>
        </div>
      </div>

      {view.truncated && (
        <div className="banner banner-warn mt-3.5">
          <strong className="font-[650]">This list is capped.</strong>{' '}
          More choke points exist than are shown. A list that stops at a round
          number looks the same as one that happened to end there, so it is said
          rather than left to be noticed.
        </div>
      )}

      <h2 className={H2}>The worklist</h2>
      <p className="text-ink2 text-[12px] mb-2.5">
        Every finding here sits on a <strong className="font-[650]">cut</strong> of at
        least one path. Findings that only reduce exploitability are deliberately
        absent — they are worth doing and they do not sever anything, so putting
        them on this page would promise a closure it cannot deliver.
      </p>

      <div className={TABLE_CARD}>
        <table className="w-full border-collapse">
          <thead>
            <tr>
              <th className={`${TH} w-[80px] text-right`}>Severs</th>
              <th className={`${TH} w-[110px] text-right`}>Worth</th>
              <th className={`${TH} w-[90px]`}>Severity</th>
              <th className={`${TH} w-[130px]`}>Check</th>
              <th className={TH}>Title</th>
              <th className={`${TH} w-[110px]`}>System</th>
              <th className={`${TH} w-[120px]`}>Ownership</th>
              <th className={`${TH} w-[90px]`}>State</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((c) => (
              <tr key={c.finding_id} className="hover:bg-panel2">
                <td className={`${TD} text-right`}>
                  {/* Coloured by CONSEQUENCE rather than by the finding's own
                      tier: a fix that severs more than one path is worth doing
                      first even when something louder severs none. */}
                  <span className={`tier ${c.paths_cut > 1 ? 'tier-P1' : 'tier-P2'}`}>
                    {c.paths_cut}
                  </span>
                </td>
                {/* WHAT CLOSING IT IS WORTH, and an em dash wherever that
                    cannot be said. `money(0)` renders "$0", which is a claim
                    that the exposure was computed and came to nothing; this is
                    the absence of a computation, and the two must not look
                    alike. See frontend/src/lib/pricing.ts. */}
                <td className={`${TD} text-right font-mono`}>
                  {c.ale_severed ? money(c.ale_severed) : UNPRICED_CELL}
                </td>
                <td className={TD}>
                  <span className={`pill sev-${c.severity ?? 'INFO'}`}>{c.severity}</span>
                </td>
                <td className={`${TD} font-mono text-[12px]`}>
                  {/* To the FINDING, not the check definition. This row is one
                      defect on one system; the definition is reachable from the
                      finding's own page. */}
                  <Link className={LINK} to={`/findings/${c.finding_id}`}>{c.check_id}</Link>
                </td>
                <td className={TD}>
                  {c.title}
                  {/* The consequence, per scenario, in the words the graph can
                      actually support: how many of how many routes this closes.
                      "1 of 4" is the sentence that stops somebody reading a
                      partial cut as a closure. */}
                  {c.scenario_detail && c.scenario_detail.length > 0 ? (
                    <div className="text-ink3 text-[12px]">
                      {c.scenario_detail.map((s) => (
                        <span key={s.scenario} className="mr-3">
                          {s.severs_all
                            ? `closes ${s.scenario} outright`
                            : `${s.scenario}: ${s.paths_cut} of ${s.paths_open} routes`}
                        </span>
                      ))}
                    </div>
                  ) : c.scenarios.length > 0 && (
                    <div className="text-ink3 text-[12px]">
                      ends at {c.scenarios.join(', ')}
                    </div>
                  )}
                </td>
                <td className={`${TD} font-mono text-[12px]`}>
                  {c.sid ?? '—'}{c.client ? `/${c.client}` : ''}
                </td>
                <td className={TD}>
                  <span className={`own own-${c.remediation_owner}`}>
                    {OWNER_SHORT[c.remediation_owner]}
                  </span>
                </td>
                <td className={TD}>
                  <span className={`pill st st-${c.state}`}>
                    {c.state.replace(/_/g, ' ')}
                  </span>
                </td>
              </tr>
            ))}
            {rows.length === 0 && (
              <tr>
                <td className="p-9 text-center text-ink2" colSpan={7}>
                  {/* An empty worklist here is a real result and reads badly if
                      it is not explained: it means no OPEN path currently has a
                      cut you can close, not that the model found nothing. */}
                  No choke points. Either no path is currently open, or the open
                  ones are evidenced only on hops that do not sever them — worth
                  checking on the{' '}
                  <Link className={LINK} to="/paths">Risk Paths</Link> screen,
                  because it is a different statement from &ldquo;nothing is
                  wrong&rdquo;.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </>
  )
}
