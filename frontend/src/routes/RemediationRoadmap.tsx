/*
 * Remediation Roadmap — every open finding, sequenced into the P1–P4 action tiers.
 *
 * THE "WHAT ORDER, WHO, BY WHEN" ACROSS THE ESTATE. The per-system remediation
 * plan (on the run page) is the "how" for one change window — the exact RZ10 lines
 * and REVOKEs, grouped by change kind. This is the programme view above it: the
 * same open findings sequenced worst-first into the four action tiers, each tagged
 * with the owning team, its SLA due date, and whether it is YOURS to fix or a SAP
 * service request. It reads the stored tier and ownership, so it never disagrees
 * with the queue or a finding's owner badge, and it never drops a finding.
 */
import { useEffect, useState } from 'react'
import { Link } from 'react-router'
import { Wrench } from 'lucide-react'

import { ApiError, remediationRoadmap as fetchRoadmap } from '../api/client'
import type { RemediationRoadmapView, RoadmapItem, RoadmapWave } from '../api/types'
import { useTitle } from '../lib/title'
import { MeasuredWhen } from '../components/MeasuredWhen'

const LINK = 'text-accent hover:underline'
const CHIP = 'text-[11px] border border-line rounded px-1.5 py-0.5 shrink-0'

// P1–P4 to the severity pill that already carries the right colour.
const TIER_PILL: Record<string, string> = {
  P1: 'sev-CRITICAL', P2: 'sev-HIGH', P3: 'sev-MEDIUM', P4: 'sev-LOW',
}

function Stat({ label, value, hint, cls }: {
  label: string; value: string | number; hint?: string; cls?: string
}) {
  return (
    <div className="rounded-lg border border-cardline bg-panel px-3.5 py-2.5" title={hint}>
      <div className={`text-xl font-extrabold tabular-nums ${cls ?? 'text-ink'}`}>{value}</div>
      <div className="text-[11px] text-ink3 uppercase tracking-wide">{label}</div>
    </div>
  )
}

function Item({ it }: { it: RoadmapItem }) {
  return (
    <li className="flex items-start gap-2.5 py-2 border-b border-line last:border-0">
      <span className={`pill sev-${it.severity} shrink-0 mt-0.5`}>{it.severity}</span>
      <span className="min-w-0 grow">
        <Link className={LINK} to={`/findings/${it.finding_id}`}>{it.title}</Link>
        <span className="block text-[11px] text-ink3 font-mono truncate">
          {it.check_id}{it.sid ? <> · {it.sid}</> : null} · {it.team}
        </span>
      </span>
      <span className="flex flex-col items-end gap-0.5 shrink-0">
        <span className={`${CHIP} ${it.customer_fixable ? 'text-ok' : 'text-med'}`}>
          {it.owner_label}
        </span>
        <span className="text-[11px] text-ink3">
          {it.due_date ? `due ${it.due_date}` : 'next review'}
        </span>
      </span>
    </li>
  )
}

function Wave({ w }: { w: RoadmapWave }) {
  if (w.items.length === 0) return null
  return (
    <section className="rounded-lg border border-cardline bg-panel p-4">
      <div className="flex items-start justify-between gap-3 mb-1">
        <h2 className="text-[15px] font-semibold text-ink flex items-center gap-2">
          <span className={`pill ${TIER_PILL[w.tier] ?? 'sev-LOW'}`}>{w.tier}</span>
          {w.label} <span className="text-[12px] text-ink3 font-normal">· {w.window}</span>
        </h2>
        <span className="text-[12px] text-ink3 shrink-0">
          {w.counts.total} · <span className="text-ok">{w.counts.customer} yours</span>
          {w.counts.sap > 0 ? <> · <span className="text-med">{w.counts.sap} SAP</span></> : null}
        </span>
      </div>
      <p className="text-[12px] text-ink3 mb-2 max-w-prose">{w.blurb}</p>
      <ul>{w.items.map((it) => <Item key={it.finding_id} it={it} />)}</ul>
    </section>
  )
}

export function RemediationRoadmap() {
  useTitle('Remediation')
  const [view, setView] = useState<RemediationRoadmapView | null>(null)
  const [failure, setFailure] = useState<string | null>(null)

  useEffect(() => {
    let live = true
    fetchRoadmap()
      .then((data) => { if (live) setView(data) })
      .catch((problem) => {
        if (!live) return
        setFailure(problem instanceof ApiError
          ? problem.message : 'Could not load the remediation roadmap.')
      })
    return () => { live = false }
  }, [])

  if (failure) return <p className="text-crit">{failure}</p>
  if (!view) return <p className="text-ink2">Loading…</p>

  const t = view.totals
  return (
    <>
      <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2 mb-1">
        <Wrench size={22} className="text-accent shrink-0" />
        Remediation Roadmap
      </h1>
      <MeasuredWhen measured={t.measured} subject="scan" />
      <p className="text-ink2 mb-4 max-w-[80ch]">
        Every open finding across {t.systems} system{t.systems === 1 ? '' : 's'},
        sequenced into the four action tiers — the order to work, who owns each, and
        by when. Open a finding for its detail; the per-system plan on the run page
        has the exact changes for a single change window.
      </p>

      {t.open === 0 ? (
        <div className="banner banner-ok max-w-[80ch]">
          No open findings in scope — nothing to sequence. This reflects the latest
          scan; keep coverage and patch currency running so it stays honest.
        </div>
      ) : (
        <>
          <div className="grid gap-3 mb-5 [grid-template-columns:repeat(auto-fit,minmax(150px,1fr))]">
            <Stat label="Open findings" value={t.open} />
            <Stat label="Yours to fix" value={t.customer_fixable} cls="text-ok"
                  hint="Findings the customer can remediate directly." />
            <Stat label="SAP service request" value={t.sap_owned} cls={t.sap_owned > 0 ? 'text-med' : 'text-ink'}
                  hint="Findings SAP operates under RISE — raised as a service request, not applied by you." />
            <Stat label="Fix now (P1)" value={t.by_tier.P1 ?? 0}
                  cls={(t.by_tier.P1 ?? 0) > 0 ? 'text-crit' : 'text-ink'} hint="Treat as an incident." />
          </div>

          <div className="flex flex-col gap-3.5">
            {view.waves.map((w) => <Wave key={w.tier} w={w} />)}
          </div>
        </>
      )}
    </>
  )
}
