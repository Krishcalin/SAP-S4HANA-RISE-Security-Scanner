/*
 * Perceived Threats — everything observed from SAP LogServ, in one place.
 *
 * A DIFFERENT QUESTION FROM THE FINDINGS LIST AND THE DOMAINS. Those answer "what
 * is wrong with the configuration". This answers "what did the logs actually
 * SEE" — the retrospective detections over the gateway, HANA, ICM, network and
 * Security Audit logs, grouped by log class, plus whether LogServ is forwarding
 * each class at all.
 *
 * AN EMPTY CLASS IS NOT A CLEAN ONE. If a log class is not being forwarded, its
 * group is empty for want of data, not because nothing happened — so the LogServ
 * coverage/health section below carries exactly that signal, and the empty-state
 * text points the reader at it rather than reading silence as safety.
 */
import { useEffect, useState } from 'react'
import { Link } from 'react-router'
import { Siren } from 'lucide-react'

import { ApiError, perceivedThreats as fetchPerceivedThreats } from '../api/client'
import type { PerceivedThreatsView, ThreatGroup, ThreatRow } from '../api/types'
import { useTitle } from '../lib/title'
import { MeasuredWhen } from '../components/MeasuredWhen'

const CARD = 'rounded-lg border border-cardline bg-panel p-4'
const GRID = 'grid gap-3.5 [grid-template-columns:repeat(auto-fit,minmax(420px,1fr))]'
const LINK = 'text-accent hover:underline'
const _SEV = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

function Counts({ counts }: { counts: Record<string, number> }) {
  const shown = _SEV.filter((s) => (counts[s] ?? 0) > 0)
  if (shown.length === 0) return null
  return (
    <div className="flex flex-wrap gap-1.5 shrink-0">
      {shown.map((s) => (
        <span key={s} className={`pill sev-${s}`}>{counts[s]} {s}</span>
      ))}
    </div>
  )
}

function Row({ f }: { f: ThreatRow }) {
  return (
    <li className="flex items-start gap-2.5 py-2 border-b border-line last:border-0">
      <span className={`pill sev-${f.severity} shrink-0 mt-0.5`}>{f.severity}</span>
      {/* The tier is what ordered this row, shown rather than left as invisible
          reasoning behind the rank. */}
      <span className="shrink-0 mt-0.5 text-[11px] font-mono text-ink3 w-[22px]">
        {f.priority_tier ?? '—'}
      </span>
      <span className="min-w-0">
        <Link className={LINK} to={`/findings/${f.id}`}>{f.title}</Link>
        <span className="block text-[11px] text-ink3 font-mono truncate">
          {f.check_id}{f.sid ? <> · {f.sid}</> : null}
        </span>
      </span>
    </li>
  )
}

function GroupCard({ group, empty }: { group: ThreatGroup; empty: string }) {
  return (
    <section className={CARD}>
      <div className="flex items-start justify-between gap-3 mb-1">
        <h2 className="text-[15px] font-semibold text-ink">{group.label}</h2>
        {group.total > 0 && <Counts counts={group.counts} />}
      </div>
      <p className="text-[12px] text-ink3 mb-2 max-w-prose">{group.blurb}</p>
      {group.findings.length === 0 ? (
        <p className="text-[13px] text-ink2 max-w-prose">{empty}</p>
      ) : (
        <>
          <ul className="mt-1">
            {group.findings.map((f) => <Row key={f.id} f={f} />)}
          </ul>
          <p className="mt-2.5 text-[12px] text-ink3">
            {group.total} observation{group.total === 1 ? '' : 's'} in this class.
          </p>
        </>
      )}
    </section>
  )
}

export function PerceivedThreats() {
  useTitle('Perceived Threats')
  const [view, setView] = useState<PerceivedThreatsView | null>(null)
  const [failure, setFailure] = useState<string | null>(null)

  useEffect(() => {
    let live = true
    fetchPerceivedThreats()
      .then((data) => { if (live) setView(data) })
      .catch((problem) => {
        if (!live) return
        setFailure(problem instanceof ApiError
          ? problem.message : 'Could not load the perceived threats.')
      })
    return () => { live = false }
  }, [])

  if (failure) return <p className="text-crit">{failure}</p>
  if (!view) return <p className="text-ink2">Loading…</p>

  const nothing = view.totals.threats === 0 && view.totals.health === 0

  return (
    <>
      <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2 mb-1">
        <Siren size={22} className="text-accent shrink-0" />
        Perceived Threats
      </h1>
      <MeasuredWhen measured={view.measured} subject="view" />
      <p className="text-ink2 mb-5 max-w-[80ch]">
        What SAP LogServ actually observed — the retrospective detections over the
        gateway, HANA, ICM, network and Security Audit logs, grouped by source,
        with the config-vs-log correlation folded in (exposed <em>and</em> being
        used). {view.totals.threats} observation
        {view.totals.threats === 1 ? '' : 's'} across {view.groups.length} log
        classes. This is a read of exported log windows, not a live feed.
      </p>

      {nothing && (
        <div className="banner banner-info">
          No SAP LogServ logs have been ingested yet, so there is nothing to
          show. Upload a LogServ export (or the Security Audit Log) and this
          screen populates from the retrospective review.
        </div>
      )}

      <div className={GRID}>
        {view.groups.map((g) => (
          <GroupCard
            key={g.id}
            group={g}
            empty={'Nothing observed in this class in the reviewed window. If the '
              + 'log for this class is not being forwarded, that shows in LogServ '
              + 'coverage below — an empty list is not the same as a clean one.'}
          />
        ))}
      </div>

      <h2 className="text-[15px] font-semibold text-ink mt-7 mb-1">
        LogServ coverage &amp; health
      </h2>
      <p className="text-[12px] text-ink3 mb-2.5 max-w-[80ch]">
        Whether the observations above are complete: is LogServ forwarding each
        log class, and could the Security Audit Log answer the question at all. A
        finding here means the empty classes above are blind spots, not clean
        results.
      </p>
      <div className={GRID}>
        {view.health.map((g) => (
          <GroupCard
            key={g.id}
            group={g}
            empty={'No coverage gap recorded for this — nothing says the log is '
              + 'missing or unreadable.'}
          />
        ))}
      </div>
    </>
  )
}
