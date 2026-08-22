/*
 * Copyright (c) 2026 Krishnendu De. All Rights Reserved.
 *
 * Author : Krishnendu De
 * Coding Assistance : Claude Code
 * Code Security Assistance : Code QL
 */

import { useEffect, useState } from 'react'
import { Link } from 'react-router'
import { ApiError, chokepoints as fetchChokepoints } from '../api/client'
import type { ChokepointsView, RemediationOwner } from '../api/types'
import { useTitle } from '../lib/title'
import { Scissors } from 'lucide-react'

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
const CARD_H3 = 'text-[12px] font-semibold uppercase tracking-[.06em] text-ink3 mb-3'
const KPI = 'text-[28px] font-extrabold tracking-tight leading-none'
const KPI_NOTE = 'text-[12px] text-ink3 mt-1.5'
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

  useEffect(() => {
    let live = true
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
      {view !== null && <Body view={view} />}
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
                  {c.scenarios.length > 0 && (
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
