import { useEffect, useState } from 'react'
import { ApiError, evidenceGaps as fetchEvidenceGaps } from '../api/client'
import type { EvidenceGap, EvidenceGapsView } from '../api/types'
import { useTitle } from '../lib/title'
import { FileQuestion } from 'lucide-react'
import { CARD_TITLE, KPI, KPI_NOTE } from '../lib/ui'

/**
 * What to send next, ranked by how much of the estate is waiting on it.
 *
 * THE FACT WAS EVERYWHERE AND THE SUM WAS NOWHERE. A finding assessed on partial
 * input already carries `evidence.complete = false` and names what it could not
 * read; FindingDetail has shown that for one finding for as long as it has
 * existed. So a reader facing sixty caveated findings saw sixty separate
 * apologies and could not tell that four absent files explained most of them.
 * This screen is that addition and nothing else — no new judgement, no new
 * scanning, only the arithmetic nobody had done.
 *
 * IT RANKS INPUT, NOT RISK, and the two are easy to confuse at a glance. A
 * source at the top is one that would let many checks REACH A VERDICT. It is not
 * a source hiding many problems — what those checks will conclude is precisely
 * what is unknown, which is why the file is being asked for. Every number and
 * every word here is chosen to keep that straight: what is counted is findings
 * left UNDECIDED, the verb is "decide", and there is no figure anywhere estimating
 * what supplying a file would turn up, because the scanner has no connection to
 * SAP and would be making it up.
 *
 * TWO ROW STATES CARRY MORE MEANING THAN THEIR COUNT:
 *
 *   * NOT OBTAINABLE UNDER RISE. Five logical sources come from the layer SAP
 *     operates. The row is ranked and counted like any other, because the gap is
 *     real and an on-premise estate can close it — but a RISE customer cannot,
 *     and a worklist that told them to run an OS-level export would be handing
 *     them an item they can only fail. It says so on the row instead.
 *   * NOT A SOURCE THE LOADER KNOWS. A name a module asks for that matches no
 *     loader slot is a defect in the product, not homework for the customer: no
 *     file anyone sends will ever close it. It is called out at the top rather
 *     than sitting in the list looking like ordinary missing input.
 *
 * THE EMPTY STATE IS GOOD NEWS AND MUST READ AS SUCH. No rows means every open
 * finding reached its verdict on complete input — the one case where "nothing
 * here" is the best possible answer rather than the ambiguous one this product
 * spends so much effort telling apart.
 */

const CARD = 'rounded-lg border border-cardline bg-panel p-4'
const H2 = 'text-[15px] font-semibold text-ink mt-7 mb-2.5'
const TH = 'text-left text-[11px] font-semibold uppercase tracking-[.05em] text-ink3 px-2.5 py-2 border-b border-line'
const TD = 'px-2.5 py-2.5 border-b border-line align-top'
const TABLE_CARD = 'rounded-lg border border-cardline bg-panel overflow-x-auto'
const CODE = 'font-mono text-[12px] text-ink'

export function EvidenceGaps() {
  const [view, setView] = useState<EvidenceGapsView | null>(null)
  const [failure, setFailure] = useState<string | null>(null)

  useTitle('Evidence Gaps')

  useEffect(() => {
    let live = true
    fetchEvidenceGaps()
      .then((v) => { if (live) setView(v) })
      .catch((e: unknown) => {
        if (!live) return
        const status = e instanceof ApiError ? e.status : 0
        setFailure(status === 403
          ? 'Your account is not permitted to see the estate.'
          : `The evidence gaps could not be loaded${status ? ` (HTTP ${status})` : ''}.`)
      })
    return () => { live = false }
  }, [])

  return (
    <>
      <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2 mb-1">
        <FileQuestion size={22} className="text-accent shrink-0" />
        Evidence Gaps
      </h1>
      <p className="text-ink2 mb-5">
        Exports you have not sent, ranked by how many open findings are waiting
        on them.
      </p>

      {failure && <div className="banner banner-bad">{failure}</div>}
      {!failure && view === null && <p className="text-[13px] text-ink3">Loading…</p>}
      {view !== null && <Body view={view} />}
    </>
  )
}

function Body({ view }: { view: EvidenceGapsView }) {
  if (view.gaps.length === 0) {
    return (
      <div className={CARD}>
        <div className={CARD_TITLE}>Nothing outstanding</div>
        <p className="text-[13px] text-ink2">
          Every open finding reached its verdict on complete input. No export is
          missing for any check that ran.
        </p>
      </div>
    )
  }

  const top = view.gaps[0]
  const unknown = view.gaps.filter((g) => !g.known_to_loader)

  return (
    <>
      <div className="grid gap-3.5 [grid-template-columns:repeat(auto-fit,minmax(240px,1fr))] mb-2">
        <div className={CARD}>
          <div className={CARD_TITLE}>Findings undecided</div>
          <div className={KPI}>{view.findings_undecided}</div>
          {/* NOT THE COLUMN'S SUM, and the note says so because a reader who adds
              the column up and gets a bigger number will trust neither figure.
              One finding blocked on two exports is one undecided finding. */}
          <p className={KPI_NOTE}>
            Open findings assessed on partial input. A finding waiting on two
            exports is counted once here and appears in both rows below.
          </p>
        </div>
        <div className={CARD}>
          <div className={CARD_TITLE}>Send this first</div>
          <div className={`${KPI} font-mono text-[22px] break-all`}>{top.source}</div>
          <p className={KPI_NOTE}>
            Would let {top.findings_undecided}{' '}
            {top.findings_undecided === 1 ? 'finding' : 'findings'} across{' '}
            {top.checks} {top.checks === 1 ? 'check' : 'checks'} reach a verdict.
          </p>
        </div>
      </div>

      {/* THE STANDING CAVEAT, once, above the table rather than on every row.
          Without it the ranking reads as a severity order, which is the single
          most likely misreading of this screen. */}
      <p className="text-[12px] text-ink2 mb-4">
        These are gaps in what we could read, not findings we are predicting.
        Supplying a source lets its checks answer; it does not say what they will
        answer — some will come back clean.
      </p>

      {unknown.length > 0 && <Unknown gaps={unknown} />}

      <h2 className={H2}>Ranked by findings waiting</h2>
      <div className={TABLE_CARD}>
        <table className="w-full border-collapse text-[13px]">
          <thead>
            <tr>
              <th className={TH}>Source</th>
              <th className={TH}>Undecided</th>
              <th className={TH}>Checks</th>
              <th className={TH}>Systems</th>
              <th className={TH}>Send one of</th>
            </tr>
          </thead>
          <tbody>
            {view.gaps.map((g) => <Row key={g.source} gap={g} />)}
          </tbody>
        </table>
      </div>
    </>
  )
}

/** A name no export can satisfy. Surfaced above the worklist because it is our
 *  bug to fix, and leaving it in the list asks the customer to hunt for a file
 *  that does not exist. */
function Unknown({ gaps }: { gaps: EvidenceGap[] }) {
  return (
    <div className="banner banner-warn mb-4">
      <strong>
        {gaps.length === 1
          ? 'One source is named by a check but is not one the loader accepts'
          : `${gaps.length} sources are named by checks but are not ones the loader accepts`}
        :
      </strong>{' '}
      {gaps.map((g) => g.source).join(', ')}. No export closes these — it is a
      defect in the check, not something to collect.
    </div>
  )
}

function Row({ gap }: { gap: EvidenceGap }) {
  return (
    <tr>
      <td className={TD}>
        <span className={CODE}>{gap.source}</span>
        {!gap.obtainable_in_rise && (
          <div className="text-[11px] text-ink3 mt-1">
            SAP operates this layer under RISE — raise it with them rather than
            exporting it yourself.
          </div>
        )}
        {gap.feeds.length > 0 && (
          <div className="text-[11px] text-ink3 mt-1">
            Feeds {gap.feeds.join(', ')}
          </div>
        )}
      </td>
      <td className={`${TD} font-mono tabular-nums`}>{gap.findings_undecided}</td>
      <td className={`${TD} font-mono tabular-nums`}>{gap.checks}</td>
      <td className={`${TD} font-mono tabular-nums`}>{gap.systems}</td>
      <td className={TD}>
        {gap.files_accepted.length > 0
          ? <span className={CODE}>{gap.files_accepted.join(' · ')}</span>
          : <span className="text-ink3">—</span>}
      </td>
    </tr>
  )
}
