/*
 * Patch Currency — how far behind the estate has fallen on SAP Security Notes.
 *
 * A LATENCY VIEW, NOT A PERCENTAGE. The Vulnerabilities screen already counts the
 * missing notes; this answers the question a board asks instead — how CURRENT are
 * we — from the one fact a missing note reliably carries: its release date. The
 * headline is a band with stated criteria (oldest unapplied, actively-exploited-
 * and-open, support-package age), never a "percent patched" (no offline export
 * knows the denominator).
 *
 * NEVER "CURRENT" WHEN WE DID NOT LOOK. With no applied-notes export the server
 * reports `not_assessed`, and this screen says so rather than showing a reassuring
 * zero. A dateless note is counted apart, never aged by guess.
 */
import { useEffect, useState } from 'react'
import { CalendarClock } from 'lucide-react'

import { ApiError, patchCurrency as fetchPatchCurrency } from '../api/client'
import type { PatchAgeBand, PatchBand, PatchCurrencyView, PatchNoteFact } from '../api/types'
import { useTitle } from '../lib/title'
import { MeasuredWhen } from '../components/MeasuredWhen'

const CARD = 'rounded-lg border border-cardline bg-panel p-4'
const GRID = 'grid gap-3.5 [grid-template-columns:repeat(auto-fit,minmax(260px,1fr))]'

const BAND: Record<PatchBand, { label: string; cls: string; note: string }> = {
  current: {
    label: 'Current', cls: 'text-ok',
    note: 'No catalogued SAP Security Note is outstanding, and the support-package '
      + 'stack is within its age threshold.',
  },
  behind: {
    label: 'Behind', cls: 'text-ink2',
    note: 'Some notes are missing, but none are HotNews, actively exploited, or '
      + 'outstanding beyond six months.',
  },
  lagging: {
    label: 'Lagging', cls: 'text-med',
    note: 'A HotNews note is missing, a note has been outstanding over six months, '
      + 'or the support-package stack is past its age threshold.',
  },
  critically_behind: {
    label: 'Critically behind', cls: 'text-crit',
    note: 'An actively-exploited note is unapplied, or a note has been outstanding '
      + 'over a year.',
  },
  not_assessed: {
    label: 'Not assessed', cls: 'text-ink3',
    note: 'No applied-notes export was supplied, so the patch level could not be '
      + 'determined. This is not the same as current.',
  },
}

// Bar fill per age band — the established inline-token approach (see Meter.tsx).
const BAND_FILL: Record<string, string> = {
  fresh: 'var(--ok)', recent: 'var(--ok)', ageing: 'var(--med)',
  old: 'var(--high)', over_a_year: 'var(--crit)',
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

function noteLine(f: PatchNoteFact): string {
  const bits: string[] = [`Note ${f.note}`]
  if (typeof f.age_days === 'number') bits.push(`${f.age_days} days unapplied`)
  if (f.released) bits.push(`released ${f.released}`)
  if (f.cvss != null) bits.push(`CVSS ${f.cvss}`)
  return bits.join(' · ')
}

function NoteList({ notes }: { notes: PatchNoteFact[] }) {
  return (
    <ul>
      {notes.map((f) => (
        <li key={f.note}
            className="flex items-center gap-2.5 py-2 border-b border-line last:border-0">
          {f.exploited && <span className="pill sev-CRITICAL shrink-0">exploited</span>}
          <span className="font-mono text-[13px] text-ink min-w-0 grow">{noteLine(f)}</span>
        </li>
      ))}
    </ul>
  )
}

function AgeBands({ bands }: { bands: PatchAgeBand[] }) {
  const max = Math.max(1, ...bands.map((b) => b.count))
  return (
    <section className={CARD}>
      <h2 className="text-[15px] font-semibold text-ink mb-1">
        How long missing notes have been outstanding
      </h2>
      <p className="text-[12px] text-ink3 mb-2.5 max-w-prose">
        Each missing note aged from its SAP release date. A note open over a year is
        a patch-governance failure on its own, separate from its severity.
      </p>
      <div className="flex flex-col gap-2">
        {bands.map((b) => (
          <div key={b.id} className="flex items-center gap-3">
            <span className="text-[12px] text-ink2 w-[96px] shrink-0">{b.label}</span>
            <div className="h-3 bg-panel2 rounded grow overflow-hidden">
              <i className="block h-full rounded"
                 style={{ width: `${(b.count / max) * 100}%`, background: BAND_FILL[b.id] ?? 'var(--accent)' }} />
            </div>
            <span className="text-[12px] text-ink3 tabular-nums w-[28px] text-right">{b.count}</span>
          </div>
        ))}
      </div>
    </section>
  )
}

export function PatchCurrency() {
  useTitle('Patch Currency')
  const [view, setView] = useState<PatchCurrencyView | null>(null)
  const [failure, setFailure] = useState<string | null>(null)

  useEffect(() => {
    let live = true
    fetchPatchCurrency()
      .then((data) => { if (live) setView(data) })
      .catch((problem) => {
        if (!live) return
        setFailure(problem instanceof ApiError
          ? problem.message : 'Could not load the patch-currency view.')
      })
    return () => { live = false }
  }, [])

  if (failure) return <p className="text-crit">{failure}</p>
  if (!view) return <p className="text-ink2">Loading…</p>

  const b = BAND[view.band] ?? BAND.not_assessed
  const sp = view.sp_stack
  const spYears = sp?.age_days != null ? (sp.age_days / 365).toFixed(1) : null

  return (
    <>
      <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2 mb-1">
        <CalendarClock size={22} className="text-accent shrink-0" />
        Patch Currency
      </h1>
      <MeasuredWhen measured={view.totals.measured} subject="scan" />
      <p className="text-ink2 mb-4 max-w-[80ch]">
        How current the estate is on SAP Security Notes — a latency view over the
        missing-note findings, not a percentage. The band below is a verdict with
        stated criteria; the figures are the facts it rests on.
      </p>

      <section className={`${CARD} mb-4`}>
        <div className="text-[11px] uppercase tracking-wide text-ink3">Patch currency</div>
        <div className={`text-2xl font-extrabold ${b.cls}`}>{b.label}</div>
        <p className="text-[13px] text-ink2 mt-1 max-w-[80ch]">{b.note}</p>
      </section>

      {!view.assessed ? (
        <div className="banner banner-info max-w-[80ch]">
          No applied-notes export (the SNOTE / applied-notes list) has been scanned,
          so what is implemented is unknown and currency cannot be judged. Supply
          that export and this screen reports how far behind the estate is.
        </div>
      ) : (
        <>
          <div className={`${GRID} mb-5`}>
            <Stat label="Notes outstanding" value={view.totals.missing}
                  hint="Distinct catalogued SAP Security Notes not recorded as applied." />
            <Stat label="Oldest unapplied"
                  value={view.oldest?.age_days != null ? `${view.oldest.age_days} d` : '—'}
                  cls={view.oldest && view.oldest.age_days != null && view.oldest.age_days > 365 ? 'text-crit' : 'text-ink'}
                  hint="Days since the oldest missing note was released by SAP." />
            <Stat label="Exploited & open" value={view.exploited_missing.count}
                  cls={view.exploited_missing.count > 0 ? 'text-crit' : 'text-ink'}
                  hint="Missing notes for vulnerabilities known to be exploited in the wild." />
            {spYears != null && (
              <Stat label="SP stack age" value={`${spYears} yr`}
                    cls={view.sp_out_of_date ? 'text-med' : 'text-ink'}
                    hint={`SAP_BASIS ${sp?.release ?? ''} ${sp?.sp ?? ''}, released ${sp?.sp_release_date ?? 'unknown'}.`} />
            )}
          </div>

          {view.totals.missing === 0 && (
            <div className="banner banner-ok max-w-[80ch] mb-4">
              No catalogued SAP Security Note is outstanding in scope. This is a
              floor, not a clearance — the catalogue is a curated subset (below).
            </div>
          )}

          {view.exploited_missing.count > 0 && (
            <section className={`${CARD} mb-4`}>
              <h2 className="text-[15px] font-semibold text-crit mb-1">
                Actively exploited and still open
              </h2>
              <p className="text-[12px] text-ink3 mb-2 max-w-prose">
                The highest-urgency items: a fix exists, the vulnerability is being
                exploited in the wild, and the note is not applied here.
              </p>
              <NoteList notes={view.exploited_missing.notes} />
            </section>
          )}

          {view.oldest && view.oldest.age_days != null && (
            <section className={`${CARD} mb-4`}>
              <h2 className="text-[15px] font-semibold text-ink mb-1">Oldest unapplied note</h2>
              <p className="font-mono text-[13px] text-ink2">{noteLine(view.oldest)}</p>
            </section>
          )}

          {view.totals.dated > 0 && (
            <div className="mb-4"><AgeBands bands={view.age_bands} /></div>
          )}

          {view.undated.count > 0 && (
            <p className="text-[12px] text-ink3 mb-4 max-w-[80ch]">
              {view.undated.count} missing note{view.undated.count === 1 ? '' : 's'}{' '}
              carried no release date in the catalogue and {view.undated.count === 1 ? 'is' : 'are'}{' '}
              counted apart — aged by guess, {view.undated.count === 1 ? 'it' : 'they'} would be invented, not measured.
            </p>
          )}

          {sp && (
            <section className={`${CARD} mb-4`}>
              <h2 className="text-[15px] font-semibold text-ink mb-1">Support-package stack</h2>
              <p className="text-[13px] text-ink2 max-w-[80ch]">
                SAP_BASIS {sp.release ?? '—'} {sp.sp ?? ''}, released {sp.sp_release_date ?? 'unknown'}
                {sp.age_days != null ? ` — ${sp.age_days} days old` : ''}
                {view.sp_out_of_date
                  ? '. Past the age threshold: the base layer is years behind, independent of any single note.'
                  : '. Within the age threshold.'}
              </p>
            </section>
          )}
        </>
      )}

      {view.catalogue && (
        <p className="text-[12px] text-ink3 max-w-[80ch]">
          Measured against a curated catalogue of {view.catalogue.catalogue_size ?? 'the significant'}{' '}
          notes swept through {view.catalogue.curated_through ?? 'a fixed date'} — the most severe and
          actively-exploited, not SAP's full Patch Day history. A clean result is a floor, not a
          clearance; confirm full patch status in SAP Maintenance Planner.
        </p>
      )}
    </>
  )
}
