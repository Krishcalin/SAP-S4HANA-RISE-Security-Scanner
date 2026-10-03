/*
 * Per-control audit evidence for one compliance framework.
 *
 * The Compliance screen answers "which controls carry findings" (a gap map). This
 * answers the auditor's actual question for ONE framework: for every control we
 * map, is there a GAP, is it CLEAR, was it NOT TESTED, or NOT MAPPED — and, where
 * there is a gap, the findings that prove it.
 *
 * CLEAR IS NOT "COMPLIANT". It means the checks that feed the control ran and
 * found nothing — an observation, never an assertion about the control
 * environment. NOT TESTED (the feeding checks did not run) is a different
 * sentence and only one of them is reassuring; the two must never render alike,
 * and no percentage is computed.
 */
import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router'
import { ClipboardCheck, Download } from 'lucide-react'

import {
  ApiError, complianceDrift as fetchDrift, complianceEvidence as fetchEvidence,
  evidencePackHref,
} from '../api/client'
import type {
  ControlChange, ControlDriftView, ControlEntry, ControlEvidenceView, ControlStatus,
} from '../api/types'
import { useTitle } from '../lib/title'
import { MeasuredWhen } from '../components/MeasuredWhen'

const CARD = 'rounded-lg border border-cardline bg-panel p-4'
const LINK = 'text-accent hover:underline'
const _SEV = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

const STATUS: Record<ControlStatus, { label: string; cls: string }> = {
  gap: { label: 'Gap', cls: 'text-crit' },
  clear: { label: 'Clear', cls: 'text-ok' },
  not_tested: { label: 'Not tested', cls: 'text-med' },
  not_mapped: { label: 'Not mapped', cls: 'text-ink3' },
}

const CHANGE: Partial<Record<ControlChange, { label: string; cls: string }>> = {
  newly_failing: { label: '↑ newly failing', cls: 'text-crit' },
  remediated: { label: '↓ remediated', cls: 'text-ok' },
  stopped_testing: { label: '⚠ stopped testing', cls: 'text-med' },
  started_testing: { label: 'now tested', cls: 'text-ink3' },
}

function ChangeBadge({ change }: { change?: ControlChange }) {
  const c = change ? CHANGE[change] : undefined
  if (!c) return null
  return <span className={`shrink-0 text-[10px] font-semibold ${c.cls}`}>{c.label}</span>
}

function StatusPill({ status }: { status: ControlStatus }) {
  const s = STATUS[status] ?? STATUS.not_mapped
  return (
    <span className={`shrink-0 text-[11px] font-semibold uppercase tracking-wide px-2 py-0.5 rounded border border-line bg-panel2 ${s.cls}`}>
      {s.label}
    </span>
  )
}

function Counts({ counts }: { counts: Record<string, number> }) {
  const shown = _SEV.filter((s) => (counts[s] ?? 0) > 0)
  if (shown.length === 0) return null
  return (
    <div className="flex flex-wrap gap-1.5 shrink-0">
      {shown.map((s) => <span key={s} className={`pill sev-${s}`}>{counts[s]} {s}</span>)}
    </div>
  )
}

function Control({ c, change }: { c: ControlEntry; change?: ControlChange }) {
  return (
    <section className={CARD}>
      <div className="flex items-start justify-between gap-3 mb-1">
        <h2 className="text-[15px] font-semibold text-ink flex items-baseline gap-2 min-w-0">
          <span className="font-mono text-[12px] text-ink3 shrink-0">{c.id}</span>
          <span className="truncate">{c.name}</span>
        </h2>
        <div className="flex items-center gap-2 shrink-0">
          <ChangeBadge change={change} />
          {c.total > 0 && <Counts counts={c.counts} />}
          <StatusPill status={c.status} />
        </div>
      </div>
      {c.themes.length > 0 && (
        <p className="text-[11px] text-ink3 mb-2">Tested via: {c.themes.join(', ')}</p>
      )}
      {c.status === 'clear' && (
        <p className="text-[13px] text-ink2 max-w-prose">
          The checks that feed this control ran and produced no finding. This is an
          observation that we looked — not an assertion that the control is met.
        </p>
      )}
      {c.status === 'not_tested' && (
        <p className="text-[13px] text-ink2 max-w-prose">
          The checks that feed this control did not run — the export they need was
          not supplied. This control was <strong>not tested</strong>.
        </p>
      )}
      {c.status === 'not_mapped' && (
        <p className="text-[13px] text-ink2 max-w-prose">
          Nothing this product checks maps to this control.
        </p>
      )}
      {c.findings.length > 0 && (
        <ul className="mt-1">
          {c.findings.map((f) => (
            <li key={f.id ?? f.check_id}
                className="flex items-start gap-2.5 py-2 border-b border-line last:border-0">
              <span className={`pill sev-${f.severity} shrink-0 mt-0.5`}>{f.severity}</span>
              <span className="min-w-0">
                {f.id != null
                  ? <Link className={LINK} to={`/findings/${f.id}`}>{f.title}</Link>
                  : <span className="text-ink">{f.title}</span>}
                <span className="block text-[11px] text-ink3 font-mono truncate">
                  {f.check_id}{f.sid ? <> · {f.sid}</> : null}
                </span>
                {f.affected_items.length > 0 && (
                  <span className="block text-[11px] text-ink3 truncate">
                    {f.affected_items.join(' · ')}
                  </span>
                )}
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}

function DriftSummary({ drift }: { drift: ControlDriftView }) {
  if (!drift.has_baseline) {
    return (
      <p className="text-[13px] text-ink3 mb-4 max-w-[80ch]">
        No previous complete scan to compare against yet — control drift appears
        once a second scan has run.
      </p>
    )
  }
  const b = drift.totals.by_change
  const parts: string[] = []
  if (b.newly_failing) parts.push(`${b.newly_failing} newly failing`)
  if (b.remediated) parts.push(`${b.remediated} remediated`)
  if (b.stopped_testing) parts.push(`${b.stopped_testing} stopped testing`)
  if (b.started_testing) parts.push(`${b.started_testing} now tested`)
  return (
    <p className="text-[13px] text-ink2 mb-4 max-w-[80ch]">
      <strong className="font-semibold">Since the previous scan:</strong>{' '}
      {parts.length ? parts.join(' · ') : 'no control changed status'}.
    </p>
  )
}

export function ComplianceEvidence() {
  const { framework = '' } = useParams()
  useTitle('Control evidence')
  const [view, setView] = useState<ControlEvidenceView | null>(null)
  const [drift, setDrift] = useState<ControlDriftView | null>(null)
  const [failure, setFailure] = useState<string | null>(null)

  useEffect(() => {
    let live = true
    setView(null)
    setDrift(null)
    setFailure(null)
    fetchEvidence(framework)
      .then((data) => { if (live) setView(data) })
      .catch((problem) => {
        if (!live) return
        setFailure(problem instanceof ApiError && problem.status === 404
          ? 'Unknown compliance framework.'
          : problem instanceof ApiError ? problem.message
          : 'Could not load the control evidence.')
      })
    // Drift is supplementary — a failure here must not blank the evidence.
    fetchDrift(framework).then((d) => { if (live) setDrift(d) }).catch(() => {})
    return () => { live = false }
  }, [framework])

  if (failure) return <p className="text-crit">{failure}</p>
  if (!view) return <p className="text-ink2">Loading…</p>

  const t = view.totals.by_status
  const changeById = new Map((drift?.controls ?? []).map((c) => [c.id, c.change]))

  return (
    <>
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <Link className={`${LINK} text-[12px]`} to="/compliance">← Compliance posture</Link>
        {/* A download, not a route: the endpoint returns the pack as an HTML
            attachment, so a plain anchor saves it with the session cookie. */}
        <a className={`${LINK} text-[12px] inline-flex items-center gap-1`}
           href={evidencePackHref(framework)} download>
          <Download size={13} className="shrink-0" /> Download evidence pack (HTML)
        </a>
      </div>
      <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2 mb-1 mt-1">
        <ClipboardCheck size={22} className="text-accent shrink-0" />
        {view.name}
      </h1>
      <p className="text-[12px] text-ink3 mb-1">{view.subtitle}</p>
      <MeasuredWhen measured={view.totals.measured} subject="scan" />
      <p className="text-ink2 mb-3 max-w-[80ch]">
        Per-control audit evidence across the {view.totals.controls} control
        {view.totals.controls === 1 ? '' : 's'} this product maps for {view.name}:{' '}
        <span className="text-crit font-semibold">{t.gap ?? 0} gap</span> ·{' '}
        <span className="text-ok font-semibold">{t.clear ?? 0} clear</span> ·{' '}
        <span className="text-med font-semibold">{t.not_tested ?? 0} not tested</span>
        {t.not_mapped ? <> · {t.not_mapped} not mapped</> : null}.
      </p>

      <div className="banner banner-warn max-w-[80ch] mb-4">
        <strong className="font-semibold">Clear is not a certification.</strong>{' '}
        <span className="text-ink2">
          A control reads <em>clear</em> when the checks feeding it ran and found
          nothing — not that the control is met. <em>Not tested</em> means those
          checks did not run. No percentage is computed.
        </span>
      </div>

      {drift && <DriftSummary drift={drift} />}

      <div className="grid gap-3 [grid-template-columns:repeat(auto-fit,minmax(460px,1fr))]">
        {view.controls.map((c) => <Control key={c.id} c={c} change={changeById.get(c.id)} />)}
      </div>
    </>
  )
}
