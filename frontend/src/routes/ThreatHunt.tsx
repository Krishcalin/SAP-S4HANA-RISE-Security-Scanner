/*
 * Threat Hunt — for every actively-exploited SAP note the estate has NOT applied,
 * the indicators to hunt for in the logs it already exported.
 *
 * THE BRIDGE THIS SCREEN IS. Patch Currency / Vulnerabilities say which exploited
 * note is missing; Perceived Threats says what the logs observed. Neither says:
 * given you are exposed to this exploited CVE, here is what to SEARCH your logs
 * for. This does — and, crucially, says whether the log you'd search was even
 * supplied (`huntable`), so a hunt you cannot run reads as "supply this log", not
 * as nothing-found.
 *
 * IT ASSERTS NO COMPROMISE. A matched indicator is evidence to investigate; an
 * empty short window is not an all-clear. The banner says so, in those words.
 */
import { useEffect, useState } from 'react'
import { Crosshair } from 'lucide-react'

import { ApiError, threatHunt as fetchThreatHunt } from '../api/client'
import type { ThreatHuntLog, ThreatHuntPack, ThreatHuntView, ThreatIndicator } from '../api/types'
import { useTitle } from '../lib/title'
import { MeasuredWhen } from '../components/MeasuredWhen'

const CARD = 'rounded-lg border border-cardline bg-panel p-4'

function huntableLabel(h: boolean | null): { text: string; cls: string } {
  if (h === true) return { text: 'huntable now', cls: 'text-ok' }
  if (h === false) return { text: 'log not supplied', cls: 'text-med' }
  return { text: 'coverage unknown', cls: 'text-ink3' }
}

function suppliedMark(s: boolean | null): { text: string; cls: string } {
  if (s === true) return { text: 'supplied', cls: 'text-ok' }
  if (s === false) return { text: 'not supplied', cls: 'text-med' }
  return { text: 'unknown', cls: 'text-ink3' }
}

function Indicator({ ind }: { ind: ThreatIndicator }) {
  const m = suppliedMark(ind.log_supplied)
  return (
    <li className="py-2 border-b border-line last:border-0">
      <div className="flex items-center gap-2 mb-0.5">
        <span className="text-[11px] font-mono text-ink3">{ind.log_label}</span>
        <span className={`text-[10px] font-semibold ${m.cls}`}>· {m.text}</span>
      </div>
      <div className="text-[13px] text-ink font-mono">{ind.signature}</div>
      {ind.meaning && <div className="text-[12px] text-ink3 mt-0.5 max-w-prose">{ind.meaning}</div>}
    </li>
  )
}

function ThreatCard({ t }: { t: ThreatHuntPack }) {
  const h = huntableLabel(t.huntable)
  return (
    <section className={CARD}>
      <div className="flex items-start justify-between gap-3 mb-1">
        <h2 className="text-[15px] font-semibold text-ink min-w-0">
          <span className="font-mono text-crit">{t.cve ?? `Note ${t.note}`}</span>
          {t.name ? <span className="text-ink"> — {t.name}</span> : null}
        </h2>
        <div className="flex items-center gap-2 shrink-0">
          {t.cvss != null && <span className="pill sev-CRITICAL">CVSS {t.cvss}</span>}
          <span className={`text-[11px] font-semibold ${h.cls}`}>{h.text}</span>
        </div>
      </div>
      <p className="text-[11px] text-ink3 mb-1 font-mono">
        SAP Note {t.note}{t.references.length ? ` · ${t.references.join(' · ')}` : ''}
      </p>
      {t.campaign && (
        <p className="text-[12px] text-med mb-1">{t.campaign}</p>
      )}
      <p className="text-[13px] text-ink2 mb-2 max-w-prose">{t.summary}</p>

      <div className="text-[11px] uppercase tracking-wide text-ink3 mb-0.5">Indicators to hunt</div>
      <ul className="mb-2">
        {t.indicators.map((ind, i) => <Indicator key={i} ind={ind} />)}
      </ul>

      {t.confirm.length > 0 && (
        <>
          <div className="text-[11px] uppercase tracking-wide text-ink3 mb-0.5">Confirm &amp; respond</div>
          <ul className="list-disc pl-5">
            {t.confirm.map((c, i) => <li key={i} className="text-[12px] text-ink2 mb-0.5">{c}</li>)}
          </ul>
        </>
      )}
    </section>
  )
}

function LogHealth({ logs }: { logs: ThreatHuntLog[] }) {
  return (
    <div className="flex flex-wrap gap-2 mb-4">
      {logs.map((l) => {
        const m = suppliedMark(l.supplied)
        return (
          <span key={l.id}
                className="text-[12px] rounded border border-line bg-panel2 px-2.5 py-1">
            {l.label}: <span className={`font-semibold ${m.cls}`}>{m.text}</span>
          </span>
        )
      })}
    </div>
  )
}

export function ThreatHunt() {
  useTitle('Threat Hunt')
  const [view, setView] = useState<ThreatHuntView | null>(null)
  const [failure, setFailure] = useState<string | null>(null)

  useEffect(() => {
    let live = true
    fetchThreatHunt()
      .then((data) => { if (live) setView(data) })
      .catch((problem) => {
        if (!live) return
        setFailure(problem instanceof ApiError
          ? problem.message : 'Could not load the threat hunt.')
      })
    return () => { live = false }
  }, [])

  if (failure) return <p className="text-crit">{failure}</p>
  if (!view) return <p className="text-ink2">Loading…</p>

  const t = view.totals
  return (
    <>
      <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2 mb-1">
        <Crosshair size={22} className="text-accent shrink-0" />
        Threat Hunt
      </h1>
      <MeasuredWhen measured={t.measured} subject="scan" />
      <p className="text-ink2 mb-3 max-w-[80ch]">
        For every actively-exploited SAP note this estate has <strong>not</strong> applied,
        the indicators to hunt for in the logs it already exported.{' '}
        {!view.assessed
          ? <span className="text-med font-semibold">Patch status not assessed.</span>
          : t.exploited_missing > 0
          ? <><span className="text-crit font-semibold">{t.with_pack}</span> with a hunt pack
              {' '}· <span className="text-ok font-semibold">{t.huntable_now}</span> huntable now
              {t.without_pack > 0 ? <> · {t.without_pack} without a pack yet</> : null}.</>
          : 'None in scope.'}
      </p>

      {!view.assessed && (
        <div className="banner banner-warn max-w-[80ch] mb-4">
          <strong className="font-semibold text-med">Patch status not assessed.</strong>{' '}
          <span className="text-ink2">
            No applied-notes export was supplied, so which actively-exploited notes
            are unapplied could not be determined. An empty hunt list below means the
            exposure was not looked for — not that none exists. Supply the applied-notes
            export (and run Patch Currency) to populate this.
          </span>
        </div>
      )}

      <div className="banner banner-warn max-w-[80ch] mb-4">
        <strong className="font-semibold">A match is a lead, not a verdict.</strong>{' '}
        <span className="text-ink2">
          These indicators tell you what to search for; a hit is evidence to
          investigate, and an empty result over a short log window is not an
          all-clear. <em>Huntable</em> means the log an indicator lives in was
          supplied — where it was not, the hunt cannot run until you export it.
        </span>
      </div>

      {view.logs.length > 0 && <LogHealth logs={view.logs} />}

      {t.exploited_missing > 0 ? (
        <div className="grid gap-3.5 [grid-template-columns:repeat(auto-fit,minmax(460px,1fr))]">
          {view.threats.map((th) => <ThreatCard key={th.note} t={th} />)}
        </div>
      ) : view.assessed ? (
        <div className="banner banner-ok max-w-[80ch]">
          No actively-exploited SAP note is unapplied in scope. This is measured
          against a curated catalogue of significant notes — a floor, not a full
          clearance — so keep patch currency and the Security Audit Log review
          running.
        </div>
      ) : null}

      {view.undeclared.length > 0 && (
        <p className="text-[12px] text-ink3 mt-4 max-w-[80ch]">
          {view.undeclared.length} actively-exploited note
          {view.undeclared.length === 1 ? '' : 's'} (
          {view.undeclared.map((u) => u.cve ?? u.note).join(', ')}) {view.undeclared.length === 1 ? 'has' : 'have'}{' '}
          an authored hunt pack but target{view.undeclared.length === 1 ? 's' : ''} a stack you have
          not declared present — so exposure cannot be confirmed here. Declare the stack
          in the landscape profile to assess and hunt {view.undeclared.length === 1 ? 'it' : 'them'}.
        </p>
      )}

      {view.without_pack.length > 0 && (
        <p className="text-[12px] text-ink3 mt-4 max-w-[80ch]">
          {view.without_pack.length} actively-exploited unapplied note
          {view.without_pack.length === 1 ? '' : 's'} (
          {view.without_pack.map((w) => w.note).join(', ')}) have no hunt pack
          authored yet — the exposure is real (see Vulnerabilities / Patch
          Currency); structured indicators have not been published here, and are
          not invented.
        </p>
      )}
    </>
  )
}
