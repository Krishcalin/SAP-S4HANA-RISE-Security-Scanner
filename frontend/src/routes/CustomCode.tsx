/*
 * Custom Code — the ABAP / custom-code security posture, in one place.
 *
 * A DIFFERENT CUT OF THE FINDINGS LIST. Our statement-aware ABAP SAST and the
 * imported SAP ATC/CVA verdicts otherwise scatter into the generic queue under
 * one flat category, where the signal that makes a custom-code finding actionable
 * is lost: which weakness, which Z-object, whether a taint walk CONFIRMED it,
 * whether it is reachable from the internet, and whether it came from our scanner
 * or SAP's own. This groups them by weakness (CWE family), ranks the worst
 * objects, and keeps a scan coverage & trust section.
 *
 * AN EMPTY WEAKNESS IS NOT A CLEAN ONE. If no ABAP source (or ATC export) was
 * scanned, every group is empty for want of input — so the coverage/trust section
 * carries that signal and the empty-state text points the reader at it rather than
 * reading silence as safety.
 */
import { useEffect, useState } from 'react'
import { Link } from 'react-router'
import { FileCode2 } from 'lucide-react'

import { ApiError, customCode as fetchCustomCode } from '../api/client'
import type {
  CustomCodeGroup, CustomCodeObject, CustomCodeRow, CustomCodeView,
} from '../api/types'
import { useTitle } from '../lib/title'
import { MeasuredWhen } from '../components/MeasuredWhen'

const CARD = 'rounded-lg border border-cardline bg-panel p-4'
const GRID = 'grid gap-3.5 [grid-template-columns:repeat(auto-fit,minmax(420px,1fr))]'
const LINK = 'text-accent hover:underline'
const CHIP = 'text-[11px] text-ink3 border border-line rounded px-1.5 py-0.5 shrink-0'
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

/** Where each finding came from, and what we know about it — shown rather than
 *  left in the details nobody opens. */
function RowChips({ f }: { f: CustomCodeRow }) {
  return (
    <>
      {f.provenance === 'atc' && <span className={CHIP}>SAP ATC</span>}
      {f.confidence === 'confirmed' && (
        <span className={CHIP} title="A taint walk proved input reaches this statement.">
          confirmed
        </span>
      )}
      {f.internet_exposed === true && (
        <span className={CHIP} title="Reachable from an exposed endpoint.">
          internet-exposed
        </span>
      )}
    </>
  )
}

function Stat({ label, value, hint }: { label: string; value: string | number; hint?: string }) {
  return (
    <div className="rounded-lg border border-cardline bg-panel px-3.5 py-2.5" title={hint}>
      <div className="text-xl font-extrabold text-ink tabular-nums">{value}</div>
      <div className="text-[11px] text-ink3 uppercase tracking-wide">{label}</div>
    </div>
  )
}

function Row({ f }: { f: CustomCodeRow }) {
  return (
    <li className="flex items-start gap-2.5 py-2 border-b border-line last:border-0">
      <span className={`pill sev-${f.severity} shrink-0 mt-0.5`}>{f.severity}</span>
      <span className="shrink-0 mt-0.5 text-[11px] font-mono text-ink3 w-[22px]">
        {f.priority_tier ?? '—'}
      </span>
      <span className="min-w-0 grow">
        <Link className={LINK} to={`/findings/${f.id}`}>{f.title}</Link>
        <span className="block text-[11px] text-ink3 font-mono truncate">
          {f.check_id}{f.object ? <> · {f.object}</> : null}{f.sid ? <> · {f.sid}</> : null}
        </span>
      </span>
      <span className="flex flex-wrap gap-1 justify-end mt-0.5"><RowChips f={f} /></span>
    </li>
  )
}

function GroupCard({ group, empty }: { group: CustomCodeGroup; empty: string }) {
  return (
    <section className={CARD}>
      <div className="flex items-start justify-between gap-3 mb-1">
        <h2 className="text-[15px] font-semibold text-ink flex items-center gap-2">
          {group.label}
          {group.cwe && <span className="text-[11px] font-mono text-ink3">{group.cwe}</span>}
        </h2>
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
            {group.total} finding{group.total === 1 ? '' : 's'}
            {group.native > 0 && group.atc > 0
              ? <> · {group.native} from our scanner, {group.atc} from SAP ATC</>
              : group.atc > 0 ? <> · from SAP ATC</> : null}
          </p>
        </>
      )}
    </section>
  )
}

function WorstObjects({ objects }: { objects: CustomCodeObject[] }) {
  if (objects.length === 0) return null
  return (
    <section className={CARD}>
      <h2 className="text-[15px] font-semibold text-ink mb-1">Worst objects</h2>
      <p className="text-[12px] text-ink3 mb-2.5 max-w-prose">
        The custom programs and classes carrying the most, and most severe,
        defects. Fixing the top of this list clears the most risk per object.
      </p>
      <ul>
        {objects.map((o) => (
          <li key={o.name}
              className="flex items-center gap-2.5 py-2 border-b border-line last:border-0">
            {o.worst && <span className={`pill sev-${o.worst} shrink-0`}>{o.worst}</span>}
            <span className="font-mono text-[13px] text-ink min-w-0 grow truncate">{o.name}</span>
            <Counts counts={o.counts} />
            <span className="text-[12px] text-ink3 tabular-nums shrink-0 w-[70px] text-right">
              {o.total} total
            </span>
          </li>
        ))}
      </ul>
    </section>
  )
}

export function CustomCode() {
  useTitle('Custom Code')
  const [view, setView] = useState<CustomCodeView | null>(null)
  const [failure, setFailure] = useState<string | null>(null)

  useEffect(() => {
    let live = true
    fetchCustomCode()
      .then((data) => { if (live) setView(data) })
      .catch((problem) => {
        if (!live) return
        setFailure(problem instanceof ApiError
          ? problem.message : 'Could not load the custom-code posture.')
      })
    return () => { live = false }
  }, [])

  if (failure) return <p className="text-crit">{failure}</p>
  if (!view) return <p className="text-ink2">Loading…</p>

  const t = view.totals
  const nothing = t.findings === 0 && t.trust === 0

  return (
    <>
      <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2 mb-1">
        <FileCode2 size={22} className="text-accent shrink-0" />
        Custom Code
      </h1>
      <MeasuredWhen measured={view.measured} subject="scan" />
      <p className="text-ink2 mb-4 max-w-[80ch]">
        The security state of the customer's ABAP, in one place — our statement-aware
        SAST and the imported SAP ATC / CVA verdicts, grouped by weakness, with the
        worst objects ranked. {t.findings} finding{t.findings === 1 ? '' : 's'} across{' '}
        {t.objects} object{t.objects === 1 ? '' : 's'}. A scan of an abapGit source
        export; where no source was supplied the groups below are empty by design.
      </p>

      {!nothing && (
        <div className="grid gap-3 mb-5 [grid-template-columns:repeat(auto-fit,minmax(130px,1fr))]">
          <Stat label="Findings" value={t.findings} />
          <Stat label="Objects" value={t.objects} hint="Distinct custom programs/classes with a finding." />
          <Stat label="Our scanner" value={t.provenance.native} hint="Native ABAP SAST findings." />
          <Stat label="SAP ATC" value={t.provenance.atc} hint="Imported from SAP's Code Vulnerability Analyzer / ATC." />
          <Stat label="Taint-confirmed" value={t.confidence.confirmed} hint="Input provably reaches the statement." />
          <Stat label="Internet-exposed" value={t.exposure.exposed} hint="Reachable from an exposed endpoint." />
        </div>
      )}

      {nothing && (
        <div className="banner banner-info">
          No custom ABAP source has been scanned yet, so there is nothing to show.
          Scan an abapGit offline export (and/or supply an SAP ATC / CVA export) and
          this screen populates with the custom-code findings, grouped by weakness.
        </div>
      )}

      <div className={GRID}>
        {view.groups.map((g) => (
          <GroupCard
            key={g.id}
            group={g}
            empty={'Nothing found for this weakness. If no ABAP source was scanned, '
              + 'that shows in scan coverage below — an empty list is not the same as '
              + 'a clean one.'}
          />
        ))}
      </div>

      {view.objects.length > 0 && (
        <div className="mt-5"><WorstObjects objects={view.objects} /></div>
      )}

      <h2 className="text-[15px] font-semibold text-ink mt-7 mb-1">
        Scan coverage &amp; trust
      </h2>
      <p className="text-[12px] text-ink3 mb-2.5 max-w-[80ch]">
        Whether the view above is complete: could the scanner read and parse the
        source, how often did an in-source #NOSEC marker silence it, and was SAP's
        own ATC/CVA evidence supplied. A finding here means the empty weaknesses
        above may be blind spots, not clean results.
      </p>
      <div className={GRID}>
        {view.health.map((g) => (
          <GroupCard
            key={g.id}
            group={g}
            empty={'No coverage or trust gap recorded for this.'}
          />
        ))}
      </div>
    </>
  )
}
