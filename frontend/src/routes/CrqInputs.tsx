/*
 * Cyber Risk Quantification — the screen where a CFO's own figures replace ours.
 *
 * WHY THIS SCREEN EXISTS
 * The shipped scenario catalogue prices loss for an illustrative $1bn
 * manufacturer, and until now every customer got that company's losses. A
 * fictitious development system in the reference deployment was reported at a
 * portfolio ALE P90 of $49,634,933.91 — to the cent, from assumptions nobody in
 * the customer's building had ever seen. Every figure here is arithmetic on
 * numbers the person reading it supplied.
 *
 * THREE THINGS THIS SCREEN REFUSES TO DO
 *  1. It ships no benchmark. Not one. "$165 per breached record" reads as
 *     authoritative and cannot be defended without the study behind it, so a
 *     question left blank leaves its cost module UNPRICED and says so. An
 *     unpriced exposure disclosed beats an invented one totalled.
 *  2. It never shows a bare headline. The P90 sits beside the share of years with
 *     no loss at all, because a P90 next to a $0 median reads as a typical year.
 *  3. Recomputing does not save. A CFO trying "what if recovery took 72 hours"
 *     must not silently write that into the history the trend chart is drawn from.
 */
import { useCallback, useEffect, useState } from 'react'
import { useSearchParams } from 'react-router'

import {
  ApiError, crqControls, crqParameters, crqQuantify, crqTrend, landscapes,
  saveCrqParameters,
} from '../api/client'
import type {
  CrqControlsView, CrqParameter, CrqParametersView, CrqQuantifyResult,
  CrqTrendPoint, Landscape,
} from '../api/types'
import { LossExceedance, RiskTrend } from '../components/CrqCharts'
import {
  UNPRICED_ACTION, UNPRICED_BODY, UNPRICED_HEADLINE, resultIsPriced,
} from '../lib/pricing'
import { useTitle } from '../lib/title'
import { money } from './Risk'
import { Calculator } from 'lucide-react'

const CARD = 'rounded-lg border border-line bg-panel p-4'
const CARD_H3 = 'text-[12px] font-semibold uppercase tracking-[.06em] text-ink3 mb-3'
const KPI = 'text-[30px] font-semibold tracking-[-.02em] leading-[1.1]'
const KPI_NOTE = 'text-ink2 text-[12px] mt-1.5'
const G4 = 'grid gap-3.5 [grid-template-columns:repeat(auto-fit,minmax(210px,1fr))]'
const H2 = 'text-[15px] font-semibold text-ink mt-7 mb-2.5'
const TH = 'text-left text-[11px] font-semibold uppercase tracking-[.05em] text-ink3 px-2.5 py-2 border-b border-line'
const TD = 'px-2.5 py-2.5 border-b border-line align-top'
const TABLE_CARD = 'rounded-lg border border-line bg-panel overflow-x-auto'

/*
 * WHICH LANDSCAPE'S FIGURES THESE ARE.
 *
 * It was hardcoded to 1, which is wrong the moment a customer has two — and this
 * product's own reference deployment has two, so the screen opened on the wrong
 * one and showed every question blank. It lives in the URL rather than in state
 * because a CFO sends this screen to somebody, and a link that silently opens a
 * different landscape's money is worse than no link. Trend.tsx keeps its filters
 * in the URL for the same reason.
 */

function unitHint(unit: string): string {
  if (unit === 'currency') return 'amount'
  if (unit === 'percent') return '%'
  if (unit === 'hours') return 'hours'
  if (unit === 'count') return 'number'
  return ''
}

export function CrqInputs() {
  useTitle('Risk quantification')
  const [params, setParams] = useSearchParams()
  const [scapes, setScapes] = useState<Landscape[] | null>(null)
  const selected = Number(params.get('landscape') || 0)
  const [view, setView] = useState<CrqParametersView | null>(null)
  const [answers, setAnswers] = useState<Record<string, string>>({})
  const [result, setResult] = useState<CrqQuantifyResult | null>(null)
  const [busy, setBusy] = useState(false)
  const [failure, setFailure] = useState<string | null>(null)
  const [saved, setSaved] = useState<string | null>(null)
  const [controls, setControls] = useState<CrqControlsView | null>(null)
  const [trend, setTrend] = useState<CrqTrendPoint[] | null>(null)

  useEffect(() => {
    let live = true
    landscapes()
      .then((ls) => {
        if (!live) return
        setScapes(ls)
        if (!selected && ls.length) {
          setParams({ landscape: String(ls[0].id) }, { replace: true })
        }
      })
      .catch(() => { if (live) setScapes([]) })
    return () => { live = false }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    if (!selected) return
    let live = true
    setResult(null)
    crqParameters(selected)
      .then((v) => {
        if (!live) return
        setView(v)
        const stored = v.latest?.answers ?? {}
        setAnswers(Object.fromEntries(
          Object.entries(stored).map(([k, n]) => [k, String(n)])))
      })
      .catch((e: unknown) => {
        if (!live) return
        const status = e instanceof ApiError ? e.status : 0
        setFailure(`The question set could not be loaded${status ? ` (HTTP ${status})` : ''}.`)
      })
    return () => { live = false }
  }, [selected])

  // Separate, and each swallows its own failure: the control attribution and the
  // trend are context for the figure, not the reason anyone opened this screen.
  useEffect(() => {
    if (!selected) return
    let live = true
    setControls(null)
    crqControls(selected).then((c) => { if (live) setControls(c) }).catch(() => {})
    crqTrend(12).then((r) => { if (live) setTrend(r.points) }).catch(() => {})
    return () => { live = false }
  }, [selected])

  const numeric = useCallback((): Record<string, number> => {
    const out: Record<string, number> = {}
    for (const [k, v] of Object.entries(answers)) {
      if (v.trim() === '') continue
      const n = Number(v)
      if (Number.isFinite(n)) out[k] = n
    }
    return out
  }, [answers])

  function recompute() {
    setBusy(true)
    setFailure(null)
    setSaved(null)
    crqQuantify(selected, numeric())
      .then(setResult)
      .catch((e: unknown) => {
        const status = e instanceof ApiError ? e.status : 0
        setFailure(`The quantification could not run${status ? ` (HTTP ${status})` : ''}.`)
      })
      .finally(() => setBusy(false))
  }

  function save() {
    setBusy(true)
    setFailure(null)
    saveCrqParameters(selected, numeric(), '')
      .then((r) => {
        setSaved(`Saved as revision ${r.id}. Earlier revisions are kept, so any `
          + `figure computed from them stays explainable.`)
        return crqParameters(selected).then(setView)
      })
      .catch((e: unknown) => {
        const status = e instanceof ApiError ? e.status : 0
        setFailure(status === 403
          ? 'Your account may view these figures but not record a revision.'
          : `The revision could not be saved${status ? ` (HTTP ${status})` : ''}.`)
      })
      .finally(() => setBusy(false))
  }

  return (
    <>
      <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2 mb-1">
        <Calculator size={22} className="text-accent shrink-0" />
        Risk quantification
      </h1>
      {/* THE PROMISE IS ONLY MADE WHEN IT IS BEING KEPT.
          This sentence used to render unconditionally, and with no saved
          revision the Recompute button below priced the catalogue's illustrative
          $1bn manufacturer and showed the result directly beneath it. A claim
          that the reader can see contradicted on the same screen is worse than
          no claim. */}
      <p className="text-ink2 mb-5 max-w-[76ch]">
        {resultIsPriced(result)
          ? 'Open findings, priced in your currency using the FAIR model. Every '
            + 'figure below is arithmetic on the numbers you supply — nothing '
            + 'here is a benchmark, an industry average, or a number we invented.'
          : 'Answer as much of the question set below as you can, then Recompute. '
            + 'Until you do, no currency figure is presented as this '
            + 'organisation’s exposure.'}
      </p>

      {scapes && scapes.length > 1 && (
        <div className="flex items-center gap-2.5 mb-4">
          <label className="text-[12px] text-ink2" htmlFor="crq-landscape">
            Landscape
          </label>
          <select
            id="crq-landscape"
            className="field"
            value={selected || ''}
            onChange={(e) => setParams({ landscape: e.target.value })}
          >
            {scapes.map((l) => (
              <option key={l.id} value={l.id}>{l.name}</option>
            ))}
          </select>
          <span className="text-[12px] text-ink3">
            Financial figures are recorded per landscape — one estate, one set of
            assumptions.
          </span>
        </div>
      )}

      {scapes && scapes.length === 0 && (
        <div className="banner banner-warn">
          There are no landscapes yet, so there is nothing to quantify. Create one
          with <code>server.cli add-landscape</code> and upload a scan first.
        </div>
      )}

      {failure && <div className="banner banner-bad" role="alert">{failure}</div>}
      {saved && <div className="banner banner-ok">{saved}</div>}
      {!failure && selected > 0 && view === null && (
        <p className="text-[13px] text-ink3">Loading…</p>
      )}

      {view && selected > 0 && (
        <>
          <Questions view={view} answers={answers} setAnswers={setAnswers} />

          <div className="flex flex-wrap items-center gap-2.5 mt-4">
            <button className="btn" onClick={recompute} disabled={busy}>
              {busy ? 'Running…' : 'Recompute'}
            </button>
            <button className="btn btn-ghost" onClick={save} disabled={busy}>
              Save as a revision
            </button>
            <span className="text-[12px] text-ink3">
              Recomputing changes nothing that is stored. Only saving does.
            </span>
          </div>

          {view.latest && (
            <p className="text-[12px] text-ink3 mt-2.5">
              Showing revision {view.latest.id}, recorded{' '}
              {new Date(view.latest.created_at).toLocaleDateString()}
              {view.latest.created_by ? ` by ${view.latest.created_by}` : ''}
              {view.history.length > 1 && ` · ${view.history.length} revisions kept`}
            </p>
          )}

          {result && <Result result={result} />}
          {controls && <Controls controls={controls} />}
          {trend && trend.length > 1 && (
            <>
              <h2 className={H2}>Has the exposure actually fallen?</h2>
              <div className={CARD}><RiskTrend points={trend} /></div>
            </>
          )}
        </>
      )}
    </>
  )
}

function Questions({ view, answers, setAnswers }: {
  view: CrqParametersView
  answers: Record<string, string>
  setAnswers: (a: Record<string, string>) => void
}) {
  const groups: Record<string, CrqParameter[]> = {}
  for (const p of view.parameters) (groups[p.group] ??= []).push(p)

  return (
    <>
      {Object.entries(groups).map(([group, params]) => (
        <div key={group}>
          <h2 className={H2}>{group}</h2>
          <div className="grid gap-3.5 [grid-template-columns:repeat(auto-fit,minmax(320px,1fr))]">
            {params.map((p) => {
              const value = answers[p.key] ?? ''
              const answered = value.trim() !== ''
              return (
                <div key={p.key} className={CARD}>
                  <label className="block text-[13px] font-medium text-ink mb-1"
                         htmlFor={`crq-${p.key}`}>
                    {p.label}
                  </label>
                  <p className="text-[12px] text-ink2 leading-snug mb-2.5">{p.help}</p>
                  <div className="flex items-center gap-2">
                    <input
                      id={`crq-${p.key}`}
                      className="field flex-1 font-mono"
                      inputMode="decimal"
                      placeholder={unitHint(p.unit)}
                      value={value}
                      onChange={(e) => setAnswers({ ...answers, [p.key]: e.target.value })}
                    />
                    {/* An unanswered question is marked, not defaulted. A blank
                        that silently became a number is how a model launders its
                        assumptions into somebody else's board pack. */}
                    <span className={answered
                      ? 'csf-state csf-state-clear'
                      : 'csf-state csf-state-not_assessed'}>
                      {answered ? 'yours' : 'not answered'}
                    </span>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      ))}
    </>
  )
}

function Result({ result }: { result: CrqQuantifyResult }) {
  if (!result.computed) {
    return (
      <div className="banner banner-warn">
        This could not be quantified: {result.reason ?? 'the FAIR engine is unavailable'}.
      </div>
    )
  }
  const p = result.portfolio
  const t = result.target_portfolio
  const priced = result.priced

  // NO CUSTOMER FIGURES, NO CURRENCY TOTAL — the same rule the HTML and PDF
  // reports obey. The components table below still renders, because "which of
  // your exposures went unpriced" is exactly what this screen is for.
  if (!resultIsPriced(result)) {
    return (
      <>
        <h2 className={H2}>What this exposure is worth</h2>
        <div className="banner banner-warn">
          <strong>{UNPRICED_HEADLINE}</strong> {UNPRICED_BODY} {UNPRICED_ACTION}
        </div>
        <h2 className={H2}>What is still unpriced</h2>
        <div className={TABLE_CARD}>
          <table className="w-full border-collapse">
            <thead>
              <tr>
                <th className={TH}>FAIR-MAM cost module</th>
                <th className={TH}>What would price it</th>
              </tr>
            </thead>
            <tbody>
              {priced.unpriced.map((u) => (
                <tr key={u.module} className="hover:bg-panel2">
                  <td className={TD}>{u.module.replace(/_/g, ' ')}</td>
                  <td className={`${TD} text-[12px] text-ink2`}>{u.needs}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </>
    )
  }

  return (
    <>
      <h2 className={H2}>What this exposure is worth</h2>

      {/* THE GUARD ON THE HEADLINE. A P90 is a bad-year figure, and a P90 shown
          alone beside a zero median reads as what next year will cost. */}
      <div className="banner banner-info">
        In {(p.p_no_loss * 100).toFixed(0)}% of simulated years these scenarios
        produce <strong>no loss event at all</strong>, and the median year costs{' '}
        {money(p.ale_p50)}. The P90 below is a <strong>bad year, not a typical
        one</strong> — it is exceeded in one year out of ten. Both are true, and
        quoting either without the other misleads.
      </div>

      <div className={G4}>
        <div className={CARD}>
          <h3 className={CARD_H3}>Annual loss, P90</h3>
          <div className={`${KPI} text-ink`}>{money(p.ale_p90)}</div>
          <div className={KPI_NOTE}>exceeded in 1 year in 10</div>
        </div>
        <div className={CARD}>
          <h3 className={CARD_H3}>Average year</h3>
          <div className={`${KPI} text-ink`}>{money(p.mean_ale)}</div>
          <div className={KPI_NOTE}>mean across {p.iterations.toLocaleString()} simulated years</div>
        </div>
        <div className={CARD}>
          <h3 className={CARD_H3}>Fully hardened floor</h3>
          <div className={`${KPI} text-ok`}>{money(t.ale_p90)}</div>
          <div className={KPI_NOTE}>
            every finding closed <em>and</em> detection healthy — more than
            clearing the backlog, and never zero
          </div>
        </div>
        <div className={CARD}>
          <h3 className={CARD_H3}>Reducible by remediation</h3>
          <div className={`${KPI} text-accent`}>{money(result.reducible_ale_p90)}</div>
          <div className={KPI_NOTE}>
            the P90 gap between today and a fully remediated estate
          </div>
        </div>
      </div>

      <h2 className={H2}>The whole distribution, not one number</h2>
      <div className={CARD}>
        <LossExceedance current={p} target={t} />
      </div>

      <h2 className={H2}>Where the loss figures came from</h2>
      <div className={TABLE_CARD}>
        <table className="w-full border-collapse">
          <thead>
            <tr>
              <th className={TH}>FAIR-MAM cost module</th>
              <th className={TH}>FAIR form of loss</th>
              <th className={`${TH} text-right`}>Most likely</th>
              <th className={TH}>How it was worked out</th>
            </tr>
          </thead>
          <tbody>
            {Object.entries(priced.components).map(([name, c]) => (
              <tr key={name} className="hover:bg-panel2">
                <td className={TD}>{c.mam_module.replace(/_/g, ' ')}</td>
                <td className={`${TD} text-[12px] text-ink2`}>{c.fair_form}</td>
                <td className={`${TD} text-right font-mono`}>{money(c.band.likely)}</td>
                <td className={`${TD} text-[12px] text-ink2`}>{c.basis}</td>
              </tr>
            ))}
            {priced.unpriced.map((u) => (
              <tr key={u.module} className="hover:bg-panel2">
                <td className={TD}>{u.module.replace(/_/g, ' ')}</td>
                <td className={`${TD} text-[12px] text-ink3`}>—</td>
                <td className={`${TD} text-right`}>
                  <span className="csf-state csf-state-not_assessed">not priced</span>
                </td>
                <td className={`${TD} text-[12px] text-ink3`}>
                  Needs {u.needs}. It is left out of the figures above rather than
                  guessed, so your exposure here is real but uncounted.
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="text-[12px] text-ink3 px-3.5 py-2.5 m-0">
          Each answer becomes a range, not a point: {priced.spread.min}× to{' '}
          {priced.spread.max}× the figure you gave, peaking at it. FAIR takes
          calibrated ranges, and a single number would claim a precision none of
          these estimates has.
          {result.scale_factor !== null && (
            <> Components with no question of their own — reputational damage,
              competitive advantage — are scaled by{' '}
              {result.scale_factor.toFixed(2)}, your revenue against the
              catalogue&rsquo;s illustrative $1bn. That is a first-order
              adjustment and nothing more.</>
          )}
        </p>
      </div>

      <p className="text-[12px] text-ink3 mt-4 max-w-[80ch]">
        Computed from {result.finding_count.toLocaleString()} open findings over{' '}
        {result.simulations.toLocaleString()} Monte Carlo iterations, seed{' '}
        {result.seed}
        {result.provenance && (
          <>
            {', scenario catalogue '}
            {result.provenance.catalogue.version ?? 'unversioned'}
            {' ('}
            <span className="font-mono">
              {(result.provenance.catalogue.sha256 ?? '').slice(0, 12) || 'no digest'}
            </span>
            {'), '}
            {result.provenance.engine.kind} engine, model v
            {result.provenance.model_version}
          </>
        )}
        . Identical answers, findings, catalogue and engine reproduce this figure
        exactly &mdash; and the trend line breaks wherever any of them changed, so
        a revised assumption is never drawn as an improvement. This is an <strong>estimate built from your assumptions</strong>,
        not a measurement, and it does not determine materiality — that is a legal
        judgement your counsel makes, which the FAIR Institute is explicit about.
      </p>
    </>
  )
}


function Controls({ controls }: { controls: CrqControlsView }) {
  const v = controls.variance_management
  const u = controls.unattributed
  return (
    <>
      <h2 className={H2}>Which control the findings actually weaken</h2>
      <p className="text-[12px] text-ink2 mb-2.5 max-w-[80ch]">
        FAIR-CAM sorts controls into nine functions, and each one moves a
        different part of the model. Prevention changes how often a loss event
        happens; Detection and Response change how much it costs when it does.
        This is the answer to &ldquo;which lever would fixing these pull?&rdquo;
      </p>
      <div className={TABLE_CARD}>
        <table className="w-full border-collapse">
          <thead>
            <tr>
              <th className={TH}>Control function</th>
              <th className={TH}>FAIR-CAM domain</th>
              <th className={TH}>Moves</th>
              <th className={`${TH} text-right`}>Findings</th>
              <th className={TH}>Attribution</th>
            </tr>
          </thead>
          <tbody>
            {controls.functions.map((f) => (
              <tr key={f.id} className="hover:bg-panel2">
                <td className={TD}>
                  <div className="text-ink">{f.name}</div>
                  <div className="text-[11px] text-ink3 max-w-[38ch]">{f.definition}</div>
                </td>
                <td className={`${TD} text-[12px] text-ink2`}>{f.domain}</td>
                <td className={`${TD} font-mono text-[12px] text-ink2`}>
                  {f.factor.replace(/_/g, ' ')}
                </td>
                <td className={`${TD} text-right font-mono`}>
                  {f.status === 'not_assessed' || f.status === 'not_supplied'
                    ? <span className="text-ink3">&mdash;</span>
                    : f.findings.toFixed(1)}
                </td>
                <td className={TD}>
                  {/* not_assessed is DASHED, never a clean zero: no check this
                      product runs is evidence about it, and 0.0 drawn like a
                      measurement would say "healthy" about the unexamined. */}
                  {f.status === 'not_assessed' ? (
                    <>
                      <span className="csf-state csf-state-not_assessed">not assessed</span>
                      <div className="text-[11px] text-ink3 mt-1 max-w-[46ch]">{f.reason}</div>
                    </>
                  ) : f.status === 'not_supplied' ? (
                    /* 0.0 is what an unfed function computes, and 0.0 drawn as a
                       measurement says "healthy" about something nothing looked
                       at. Dashed, with the count replaced by an em dash above. */
                    <>
                      <span className="csf-state csf-state-not_supplied">export not supplied</span>
                      <div className="text-[11px] text-ink3 mt-1 max-w-[46ch]">
                        No module feeding this control function ran in the scans you
                        can see, so its pressure is unmeasured rather than zero.
                      </div>
                    </>
                  ) : f.status === 'clear' ? (
                    <span className="csf-state csf-state-clear">no findings</span>
                  ) : (
                    <>
                      <span className={f.confidence === 'ambiguous'
                        ? 'csf-state csf-state-not_assessed'
                        : 'csf-state csf-state-assessed'}>
                        {f.confidence === 'ambiguous' ? 'ambiguous split' : f.confidence}
                      </span>
                      <div className="text-[11px] text-ink3 mt-1">{f.themes.join(' · ')}</div>
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="text-[12px] text-ink3 px-3.5 py-2.5 m-0">
          Findings are counted <strong>fractionally</strong>: one finding whose
          theme reaches three functions contributes a third to each, so the column
          sums to the corpus rather than triple-counting it. An
          <strong> ambiguous split</strong> means the theme genuinely spans more
          than one function — least privilege both resists an action and shrinks
          its blast radius — and the weighting is a stated modelling choice, not a
          measurement.
        </p>
      </div>

      {(v.findings > 0 || u.count > 0) && (
        <div className="banner banner-info mt-3.5">
          {v.findings > 0 && (
            <>
              <strong>{v.findings.toFixed(1)} findings are Variance Management
              controls</strong> ({v.themes.join(', ')}). {v.note}{' '}
            </>
          )}
          {u.count > 0 && (
            <><strong>{u.count} findings reach no control function at all</strong>
              {' '}({u.categories.join(', ')}). {u.note}</>
          )}
        </div>
      )}
    </>
  )
}
