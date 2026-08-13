/*
 * Copyright (c) 2026 Krishnendu De. All Rights Reserved.
 *
 * Author : Krishnendu De
 * Coding Assistance : Claude Code
 * Code Security Assistance : Code QL
 */

import { useEffect, useState } from 'react'
import { Link } from 'react-router'
import { ApiError, risk } from '../api/client'
import type { CrqScenario, RiskView } from '../api/types'
import {
  UNPRICED_ACTION, UNPRICED_BODY, UNPRICED_CELL, UNPRICED_HEADLINE,
  isPriced,
} from '../lib/pricing'
import { RiskTrend } from '../components/CrqCharts'
import { useTitle } from '../lib/title'

/**
 * Financial risk exposure — the board view, ported from server/templates/risk.html.
 *
 * NOTHING ON THIS SCREEN IS COMPUTED HERE. Every figure is rendered exactly as
 * /api/risk returned it. The portfolio is an element-wise Monte-Carlo sum across
 * scenarios and is emphatically NOT the sum of the scenario percentiles below it,
 * so a client that "helpfully" totalled the visible column would print a number
 * the model never produced and cannot defend. The only arithmetic in this file is
 * the pixel height of a bar, which is presentation and is marked as such.
 *
 * THE THREE STATES ARE DELIBERATE and match the template: nothing computed yet,
 * inputs built but not simulated, and a full result. The middle one exists because
 * a blank page reads as "nothing to report" when what actually happened is that
 * the Monte-Carlo engine was not importable — which is a deployment fact the
 * operator needs, not an absence of risk.
 */

/** `crq_result.detail` is jsonb and arrives typed as Record<string, unknown>, so
 *  every read out of it is narrowed rather than asserted. A cast here would move
 *  a wrong shape from a type error into a runtime "undefined" printed as a
 *  currency figure, which is the one failure mode this screen cannot have. */
function num(v: unknown): number | null {
  return typeof v === 'number' && Number.isFinite(v) ? v : null
}
function str(v: unknown): string | null {
  return typeof v === 'string' && v !== '' ? v : null
}
function obj(v: unknown): Record<string, unknown> | null {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
    ? (v as Record<string, unknown>)
    : null
}

/**
 * Render a currency figure the way a board reads one — transcribed from
 * server/app.py `_money`, whose docstring is the reasoning.
 *
 * IT IS EXPORTED, AND THAT IS WHY IT LIVES HERE. The attack-path screens render
 * the same scenario exposure figure this screen prices, and a second hand-written
 * transcription of `_money` would drift from this one and from the server on the
 * first rounding change. One definition, on the screen the figure belongs to.
 *
 * `null` renders as an em dash rather than "$0": "not computed" and "zero risk"
 * are very different claims and the whole credibility of the screen rests on not
 * confusing them.
 *
 * THE LOCALE IS PINNED to en-US rather than the browser's. The Jinja console
 * formats with Python's `{:,}` — always a comma group and a dot decimal — and the
 * two consoles run side by side for the whole migration. A German browser reading
 * `undefined` locale would render "1.240,00" where the server-rendered page one
 * click away says "1,240.00", and a reader would reasonably conclude one of them
 * is wrong.
 */
export function money(value: number | null | undefined): string {
  if (value === null || value === undefined) return '—'
  const n = Number(value)
  if (!Number.isFinite(n)) return '—'
  const scales: [number, string][] = [[1e9, 'B'], [1e6, 'M'], [1e3, 'K']]
  for (const [limit, suffix] of scales) {
    if (Math.abs(n) >= limit) {
      const scaled = (n / limit).toLocaleString('en-US', {
        minimumFractionDigits: 2, maximumFractionDigits: 2,
      })
      return `$${scaled}${suffix}`.replace('.00', '')
    }
  }
  return `$${n.toLocaleString('en-US', { maximumFractionDigits: 0 })}`
}


const TABLE_CARD = 'rounded-lg border border-line bg-panel overflow-x-auto'
const EMPTY = 'p-9 text-center text-ink2'
const LINK = 'text-accent hover:underline'
const CARD = 'rounded-lg border border-line bg-panel p-4'
const CARD_H3 = 'text-[12px] font-semibold uppercase tracking-[.06em] text-ink3 mb-3'
const KPI = 'text-[30px] font-semibold tracking-[-.02em] leading-[1.1]'
const KPI_NOTE = 'text-ink2 text-[12px] mt-1.5'
const G4 = 'grid gap-3.5 [grid-template-columns:repeat(auto-fit,minmax(210px,1fr))]'
const H2 = 'text-[15px] font-semibold text-ink mt-7 mb-2.5'
const TH = 'text-left text-[11px] font-semibold uppercase tracking-[.05em] text-ink3 px-2.5 py-2 border-b border-line'
const TD = 'px-2.5 py-2.5 border-b border-line align-top'

export function Risk() {
  useTitle('Financial risk')
  const [view, setView] = useState<RiskView | null>(null)
  const [failure, setFailure] = useState<string | null>(null)

  useEffect(() => {
    let live = true
    risk()
      .then((v) => { if (live) setView(v) })
      .catch((e: unknown) => {
        if (!live) return
        // Branch on the status, never the message — see ApiError in api/client.ts.
        const status = e instanceof ApiError ? e.status : 0
        setFailure(status === 403
          ? 'Your account is not permitted to see the financial risk model.'
          : `The financial risk model could not be loaded${status ? ` (HTTP ${status})` : ''}.`)
      })
    return () => { live = false }
  }, [])

  return (
    <>
      <h1 className="text-[21px] font-semibold tracking-tight text-ink mb-1">
        Financial risk exposure
      </h1>
      <p className="text-ink2 mb-5">
        Findings expressed as annualised loss exposure, using a FAIR Monte-Carlo model
        over five scoped SAP loss scenarios.
      </p>

      {failure && <div className="banner banner-bad">{failure}</div>}
      {!failure && view === null && <p className="text-[13px] text-ink3">Loading…</p>}
      {view !== null && <Body view={view} />}
    </>
  )
}

function Body({ view }: { view: RiskView }) {
  const crq = view.portfolio

  if (crq === null) {
    return (
      <div className={`${CARD} p-9 text-center text-ink2`}>
        No quantification yet — upload a scan and this page populates automatically.
      </div>
    )
  }

  // Attempted but not simulated. Saying so beats a blank page, which reads as
  // "nothing to report".
  if (crq.ale_p90 === null) {
    return (
      <div className="banner banner-warn">
        <strong className="font-[650]">Scenario inputs were built but not simulated.</strong>{' '}
        {str(crq.detail.reason) ??
          'The Monte-Carlo engine was not locatable in this environment.'}{' '}
        The finding routing below still applies, and{' '}
        <strong className="font-[650]">{crq.unrouted_count}</strong> finding(s) could not
        be attributed to a specific loss scenario.
      </div>
    )
  }

  const d = crq.detail
  const organization = obj(d.organization)
  const target = obj(d.target_portfolio)
  const simulations = num(d.simulations)
  const exposureWeight = num(d.exposure_weight)

  // NO CUSTOMER FIGURES, NO CURRENCY TOTAL. The same rule the HTML and PDF
  // reports have obeyed since the report split was closed, and which this screen
  // — the one whose whole purpose is the money — did not.
  //
  // Every stored row written before loss_model existed lands here, and that is
  // correct: "we have no record of where this number came from" is not "it was
  // the customer's". The routing and the scenario table below still render,
  // because those are driven by findings and are real.
  if (!isPriced(crq)) {
    return (
      <>
        <div className="banner banner-warn">
          <strong className="font-[650]">{UNPRICED_HEADLINE}</strong>{' '}
          {UNPRICED_BODY}{' '}
          <Link className={LINK} to="/crq">{UNPRICED_ACTION}</Link>
        </div>
        <h2 className={H2}>Scenarios matched to your findings</h2>
        <p className="text-[12px] text-ink2 mb-2.5 max-w-[76ch]">
          Scenario matching is real and independent of the money: it is driven by
          your findings. Only the loss magnitude is unpriced.
        </p>
        <div className={TABLE_CARD}>
          <table className="w-full border-collapse">
            <thead>
              <tr>
                <th className={TH}>Scenario</th>
                <th className={`${TH} text-right`}>Findings routed</th>
              </tr>
            </thead>
            <tbody>
              {view.scenarios.map((s) => (
                <tr key={s.id} className="hover:bg-panel2">
                  <td className={TD}>{s.scenario_id ?? s.id}</td>
                  <td className={`${TD} text-right font-mono`}>
                    {s.input_finding_count ?? UNPRICED_CELL}
                  </td>
                </tr>
              ))}
              {view.scenarios.length === 0 && (
                <tr><td className={EMPTY} colSpan={2}>No scenarios matched.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </>
    )
  }

  return (
    <>
      <div className={G4}>
        <div className={CARD}>
          <h3 className={CARD_H3}>Annualised loss exposure</h3>
          <div className={KPI}>{money(crq.ale_p90)}</div>
          <div className={KPI_NOTE}>90th percentile · median {money(crq.ale_p50)}</div>
        </div>
        <div className={CARD}>
          <h3 className={CARD_H3}>Reducible by remediation</h3>
          <div className={`${KPI} text-ok`}>{money(num(d.reducible_ale_p90))}</div>
          {/* NOT "if the open findings were closed". fair_adapter builds this
              arm by resetting every scenario to baseline contact frequency and
              probability of action, HARDENED resistance strength, and no
              detection penalty — a fully hardened posture, which is more than
              closing today's findings and includes work a RISE customer is not
              permitted to do themselves. The old label promised a floor that
              closing the backlog would not reach. */}
          <div className={KPI_NOTE}>
            if every finding closed <em>and</em> detection were healthy
          </div>
        </div>
        <div className={CARD}>
          <h3 className={CARD_H3}>Residual after remediation</h3>
          <div className={KPI}>{money(target ? num(target.ale_p90) : null)}</div>
          <div className={KPI_NOTE}>risk that remains regardless</div>
        </div>
        <div className={CARD}>
          <h3 className={CARD_H3}>Priced on</h3>
          <div className={KPI}>{crq.input_finding_count}</div>
          <div className={KPI_NOTE}>findings — the complete set, unfiltered</div>
        </div>
      </div>

      {/* Disclosing what the model did NOT price is what separates this from vendor
          hand-waving, and it is the first thing a risk function will test. */}
      {crq.unrouted_count > 0 && (
        <div className="banner banner-info mt-3.5">
          <strong className="font-[650]">
            {crq.unrouted_count} finding(s) could not be attributed to a specific loss
            scenario
          </strong>{' '}
          and were folded conservatively into <span className="font-mono">SAP-PRIV-03</span>,
          which may overstate that scenario. They are not excluded — they are disclosed.
        </div>
      )}

      <div className="banner mt-3.5">
        <strong className="font-[650]">How to read this.</strong> A finding is not a risk:
        findings are evidence that shifts a scenario&rsquo;s factors, and no finding carries
        its own loss figure. The portfolio is an element-wise Monte-Carlo sum across
        scenarios, never a sum of percentiles. Loss ranges are{' '}
        <strong className="font-[650]">
          modelled estimates from public benchmarks, not measurements
        </strong>.
        {simulations !== null && ` ${simulations.toLocaleString('en-US')} simulations.`}
      </div>

      <h2 className={H2}>Loss scenarios</h2>
      <div className="rounded-lg border border-line bg-panel overflow-x-auto">
        <table className="w-full border-collapse">
          <thead>
            <tr>
              <th className={`${TH} w-[120px]`}>Scenario</th>
              <th className={TH}>Description</th>
              <th className={`${TH} text-right w-[120px]`}>ALE (P90)</th>
              <th className={`${TH} text-right w-[110px]`}>Median</th>
              <th className={`${TH} text-right w-[90px]`}>Findings</th>
              <th className={`${TH} w-[110px]`}>Signals</th>
            </tr>
          </thead>
          <tbody>
            {view.scenarios.map((s) => <ScenarioRow key={s.id} s={s} />)}
            {view.scenarios.length === 0 && (
              <tr>
                <td className="p-9 text-center text-ink2" colSpan={6}>
                  No scenario detail stored for this run.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* THE SHARED TREND, NOT THIS SCREEN'S OWN.
          ExposureSeries drew one continuous polyline through every run. Risk
          moves for reasons that are not remediation — a revised revenue figure,
          a changed simulation count, a dropped export that made checks self-skip
          — and a line drawn straight through such a change asserts the two ends
          are comparable. RiskTrend breaks the series wherever inputs_fingerprint
          changes, which is the guard that existed on /crq and nowhere else. */}
      <RiskTrend points={view.trend} />

      {organization !== null && (
        <>
          <h2 className={H2}>Model inputs</h2>
          <div className={CARD}>
            <dl className="grid [grid-template-columns:auto_1fr] gap-x-4 gap-y-1.5 m-0">
              {Object.entries(organization).map(([k, v]) => (
                <div key={k} className="contents">
                  <dt className="text-ink3 text-[12px]">{k.replace(/_/g, ' ')}</dt>
                  <dd className="m-0 font-mono text-[12px]">
                    {typeof v === 'number' && v > 1000
                      ? v.toLocaleString('en-US', { maximumFractionDigits: 0 })
                      : String(v)}
                  </dd>
                </div>
              ))}
              {exposureWeight !== null && (
                <div className="contents">
                  {/* RECORDED, NEVER APPLIED. server/ingest.py calls
                      compute_and_store WITHOUT revenue=, so the weight is
                      computed, stored, and multiplies nothing. It is kept
                      because removing it would erase the audit trail of a
                      number earlier versions displayed as a model input — but
                      it is no longer labelled as one. */}
                  <dt className="text-ink3 text-[12px]">
                    system criticality weight <span className="text-ink3">(recorded, not applied)</span>
                  </dt>
                  <dd className="m-0 font-mono text-[12px]">
                    {exposureWeight}{' '}
                    <span className="text-ink3">
                      — the heaviest criticality among scanned systems, not an average: a
                      landscape holding one production ledger is exposed to a
                      production-ledger loss.
                    </span>
                  </dd>
                </div>
              )}
            </dl>
          </div>
        </>
      )}
    </>
  )
}

function ScenarioRow({ s }: { s: CrqScenario }) {
  const exploited = s.detail.exploited === true
  const exposed = s.detail.exposed === true
  return (
    <tr className="hover:bg-panel2">
      <td className={`${TD} font-mono text-[12px]`}>{s.scenario_id}</td>
      <td className={TD}>{str(s.detail.name) ?? ''}</td>
      <td className={`${TD} text-right font-mono`}>{money(s.ale_p90)}</td>
      <td className={`${TD} text-right font-mono text-ink2`}>{money(s.ale_p50)}</td>
      <td className={`${TD} text-right font-mono`}>{num(s.detail.finding_count) ?? 0}</td>
      <td className={`${TD} text-[12px]`}>
        {exploited && <span className="pill sev-CRITICAL">exploited</span>}{' '}
        {exposed && <span className="pill sev-HIGH">exposed</span>}
        {!exploited && !exposed && <span className="text-ink3">—</span>}
      </td>
    </tr>
  )
}

