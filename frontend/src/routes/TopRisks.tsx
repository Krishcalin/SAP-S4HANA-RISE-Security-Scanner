/*
 * The five worst open findings in each of the twelve domains.
 *
 * A DIFFERENT QUESTION FROM THE FINDINGS LIST, and that is the whole reason
 * this screen exists. /findings answers "what is worst in the estate", sorted
 * once, and on a real estate the first five rows can all sit in one domain —
 * which tells the eleven other owners nothing. This answers "what is worst in
 * EACH domain", which is the shape somebody uses to hand out work.
 *
 * RANKED THE WAY THE CONSOLE RANKS EVERYWHERE ELSE: priority tier first,
 * severity second. The tier folds in exploitability, exposure and privilege, so
 * a "top five" built on raw severity would put an unreachable CRITICAL above an
 * actively-exploited HIGH — the wrong five, presented with more confidence than
 * the list it came from.
 *
 * AN EMPTY CARD IS FOUR DIFFERENT THINGS and they are drawn differently on
 * purpose. Only one of them is good news:
 *
 *   clear         we looked and found nothing
 *   not_supplied  we would have looked; the export never arrived
 *   not_assessed  this product does not cover it, in any run
 *   assessed      we looked, found something, and it is listed
 *
 * A page that draws the first three the same way turns two absences of evidence
 * into a clean bill of health, which is the failure this product exists to
 * prevent.
 */
import { useEffect, useState } from 'react'
import { Link } from 'react-router'
import { ListOrdered } from 'lucide-react'

import { ApiError, topRisks as fetchTopRisks } from '../api/client'
import type { TopRiskDomain, TopRisksView } from '../api/types'
import { useTitle } from '../lib/title'
import { MeasuredWhen } from '../components/MeasuredWhen'
import { stateChip } from './Domains'

const CARD = 'rounded-lg border border-cardline bg-panel p-4'
const GRID = 'grid gap-3.5 [grid-template-columns:repeat(auto-fit,minmax(420px,1fr))]'
const LINK = 'text-accent hover:underline'

/** What to say when a domain lists nothing. The state decides, never the
 *  emptiness of the list. */
function emptyWord(state: TopRiskDomain['state']): string {
  if (state === 'clear') return 'Nothing open here. This domain was assessed and came back empty.'
  if (state === 'not_supplied') return 'No risks are listed because nothing was assessed — the export this domain reads never arrived. This is not a clean result.'
  if (state === 'not_assessed') return 'Not covered by this product in any run, so nothing here is a statement about your estate.'
  return 'Nothing to show.'
}

function Row({ risk }: { risk: TopRiskDomain['shown'][number] }) {
  return (
    <li className="flex items-start gap-2.5 py-2 border-b border-line last:border-0">
      <span className={`pill sev-${risk.severity} shrink-0 mt-0.5`}>
        {risk.severity}
      </span>
      {/* The tier is what actually ordered this row, so it is shown rather
          than left as invisible reasoning behind a rank. */}
      <span className="shrink-0 mt-0.5 text-[11px] font-mono text-ink3 w-[22px]">
        {risk.priority_tier ?? '—'}
      </span>
      <span className="min-w-0">
        <Link className={LINK} to={`/findings/${risk.id}`}>{risk.title}</Link>
        <span className="block text-[11px] text-ink3 font-mono truncate">
          {risk.check_id}
          {/* The systems it lands on, because one problem on six systems is
              one risk — and the reader still has to know it is six.

              SIX SYSTEMS, NOT SIX FINDINGS. This said `{instances} systems`,
              and `instances` counts findings: a check firing in two clients of
              one system, or on two systems that share a SID across landscapes,
              made the label overstate. Measured on an eight-system estate it
              read "9 systems" while naming eight. `system_count` counts the
              systems; `instances` is shown beside it only when the two differ,
              because that difference is itself worth seeing. */}
          {risk.instances > 1
            ? <> · {risk.system_count ?? risk.systems.length} system
                {(risk.system_count ?? risk.systems.length) === 1 ? '' : 's'}
                {risk.instances !== (risk.system_count ?? risk.systems.length)
                  && ` (${risk.instances} findings)`}
                : {risk.systems.slice(0, 3).join(', ')}
                {/* "and N more" counted off the authoritative total, not off
                    the name list. Two systems sharing a SID contribute one
                    name, so "DEV, DV2, PR2 +5" beside "9 systems" left the
                    reader adding 3 and 5 and getting 8. */}
                {(risk.system_count ?? risk.systems.length)
                   > Math.min(3, risk.systems.length)
                  && ` +${(risk.system_count ?? risk.systems.length)
                          - Math.min(3, risk.systems.length)}`}</>
            : risk.sid && <> · {risk.sid}{risk.system_client ? `/${risk.system_client}` : ''}</>}
        </span>
      </span>
    </li>
  )
}

function DomainCard({ domain }: { domain: TopRiskDomain }) {
  const chip = stateChip(domain)
  return (
    <section className={CARD}>
      <div className="flex items-start justify-between gap-3 mb-2">
        <h2 className="text-[15px] font-semibold text-ink">
          <Link className="hover:underline" to={`/domains/${domain.id}`}>
            {domain.label}
          </Link>
        </h2>
        <span className={`pill ${chip.cls} shrink-0`}>{chip.text}</span>
      </div>

      {domain.shown.length === 0 ? (
        <p className="text-[13px] text-ink2 max-w-prose">
          {emptyWord(domain.state)}
        </p>
      ) : (
        <>
          <ul className="mt-1">
            {domain.shown.map((r) => <Row key={r.id} risk={r} />)}
          </ul>
          {/* "5 of 138" rather than "5". The second invites a reader to think
              they have seen the domain. */}
          <p className="mt-2.5 text-[12px] text-ink3">
            Showing {domain.shown.length} of {domain.distinct} distinct risk
            {domain.distinct === 1 ? '' : 's'}
            {domain.total !== domain.distinct && <> across {domain.total} findings</>}
            {domain.not_shown > 0 && (
              <>
                {' · '}
                <Link className={LINK} to={`/domains/${domain.id}`}>
                  {domain.not_shown} more in this domain →
                </Link>
              </>
            )}
          </p>
        </>
      )}
    </section>
  )
}

export function TopRisks() {
  useTitle('Top 5 Risks')
  const [view, setView] = useState<TopRisksView | null>(null)
  const [failure, setFailure] = useState<string | null>(null)

  useEffect(() => {
    let live = true
    fetchTopRisks()
      .then((data) => { if (live) setView(data) })
      .catch((problem) => {
        if (!live) return
        setFailure(problem instanceof ApiError
          ? problem.message : 'Could not load the top risks.')
      })
    return () => { live = false }
  }, [])

  if (failure) return <p className="text-crit">{failure}</p>
  if (!view) return <p className="text-ink2">Loading…</p>

  const listed = view.domains.reduce((n, d) => n + d.shown.length, 0)
  const unassessed = view.domains.filter(
    (d) => d.state === 'not_supplied' || d.state === 'not_assessed').length

  return (
    <>
      <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2 mb-1">
        <ListOrdered size={22} className="text-accent shrink-0" />
        Top {view.per_domain} Risks by Domain
      </h1>
      <MeasuredWhen measured={view.measured} subject="view" />
      <p className="text-ink2 mb-5 max-w-[80ch]">
        The worst {view.per_domain} open findings in each domain, ranked by
        priority tier and then severity — the same order the findings list uses,
        because the tier already accounts for exploitability, exposure and
        privilege. {listed} finding{listed === 1 ? '' : 's'} listed across{' '}
        {view.domains.length} domains.
        {unassessed > 0 && (
          <>
            {' '}
            <strong className="text-ink">
              {unassessed} domain{unassessed === 1 ? '' : 's'} listed nothing
              because nothing was assessed there
            </strong>
            {' '}— an empty card is not the same as a clean one, and each says
            which it is.
          </>
        )}
      </p>

      <div className={GRID}>
        {view.domains.map((d) => (
          <DomainCard key={d.id} domain={d} />
        ))}
      </div>
    </>
  )
}
