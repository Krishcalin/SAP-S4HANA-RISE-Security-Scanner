/*
 * Compliance posture, across every framework this product maps.
 *
 * TEN FRAMEWORKS THAT REACHED NO SCREEN. `modules/compliance_mapping.py` maps
 * findings onto ISO/IEC 27001:2022, NIST CSF 2.0, NIST SP 800-53 Rev 5, SOX
 * ITGC, DORA, CIS Controls v8, TISAX, SOC 2, EU GDPR and NERC CIP. Until this
 * page existed the only consumers were the offline HTML, PDF and PPTX
 * generators — so a customer who works in the console and never exports a
 * report saw none of it. NIST CSF had a screen because it has its own module;
 * the other nine had nowhere to appear.
 *
 * THE SENTENCE THIS PAGE MUST NEVER LET A READER FORGET, and the reason there
 * is no percentage anywhere on it: a control carrying findings has open gaps,
 * and the ABSENCE of findings against a control is not an assertion of
 * compliance with it. This product reads configuration exports, not the control
 * environment. `compliance_mapping.py` forbids a percentage in as many words,
 * and a screen is exactly where one would get invented — a progress bar, a
 * "9 of 12 controls green", a donut. None of those appear here.
 *
 * THE DENOMINATOR IS OURS, NOT THE FRAMEWORK'S. "4 of 15 controls flagged"
 * means four of the fifteen controls THIS PRODUCT MAPS, not four of the
 * hundreds ISO 27001 contains. Stated on the page, because the two readings
 * differ by an order of magnitude and only one of them is true.
 */
import { useEffect, useState } from 'react'
import { Link } from 'react-router'
import { ScrollText } from 'lucide-react'

import { ApiError, compliance as fetchCompliance } from '../api/client'
import type { ComplianceFramework, ComplianceView } from '../api/types'
import { useTitle } from '../lib/title'

const CARD = 'rounded-lg border border-cardline bg-panel p-4'
const TH = 'text-left text-[11px] font-semibold uppercase tracking-[.05em] text-ink3 px-2.5 py-2 border-b border-line'
const TD = 'px-2.5 py-2 border-b border-line align-top'
const NUM = `${TD} text-right tabular-nums`

function Framework({ framework }: { framework: ComplianceFramework }) {
  const [open, setOpen] = useState(false)
  const mapped = framework.mapped_findings > 0

  return (
    <section className={CARD}>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <h2 className="text-[15px] font-semibold text-ink">{framework.name}</h2>
          <p className="text-[12px] text-ink3">{framework.subtitle}</p>
        </div>
        <span className="shrink-0 text-[12px] text-ink2 tabular-nums">
          {/* "of the controls we map" is on the page once, above. Repeating the
              whole caveat on every card would make it wallpaper. */}
          {framework.controls_flagged} of {framework.total_controls} mapped
          control{framework.total_controls === 1 ? '' : 's'} flagged
        </span>
      </div>

      {!mapped ? (
        // NOT "compliant". Nothing mapped means nothing this product looked at
        // was evidence against this framework — which is a statement about our
        // findings, not about the customer's controls.
        <p className="mt-2 text-[13px] text-ink2 max-w-prose">
          No open finding maps to this framework. That is not a statement that
          its controls are met — only that nothing this scan produced is
          evidence against them.
        </p>
      ) : (
        <>
          <button
            type="button"
            onClick={() => setOpen(!open)}
            className="mt-2.5 text-[12px] text-accent hover:underline"
            aria-expanded={open}
          >
            {open ? 'Hide' : 'Show'} the {framework.controls.length} control
            {framework.controls.length === 1 ? '' : 's'} carrying findings
          </button>
          {open && (
            <div className="mt-2 overflow-x-auto">
              <table className="w-full border-collapse">
                <thead>
                  <tr>
                    <th className={TH}>Control</th>
                    <th className={TH}>Themes</th>
                    <th className={`${TH} text-right`}>Crit</th>
                    <th className={`${TH} text-right`}>High</th>
                    <th className={`${TH} text-right`}>Total</th>
                  </tr>
                </thead>
                <tbody>
                  {framework.controls.map((c) => (
                    <tr key={c.id}>
                      <td className={TD}>
                        <span className="font-mono text-[12px]">{c.id}</span>
                        <span className="block text-[12px] text-ink2">{c.name}</span>
                      </td>
                      <td className={`${TD} text-[12px] text-ink3`}>
                        {c.themes.join(', ')}
                      </td>
                      <td className={`${NUM} ${c.crit ? 'text-crit' : 'text-ink3'}`}>
                        {c.crit || '—'}
                      </td>
                      <td className={`${NUM} ${c.high ? 'text-high' : 'text-ink3'}`}>
                        {c.high || '—'}
                      </td>
                      <td className={`${NUM} font-semibold`}>{c.total}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </section>
  )
}

export function Compliance() {
  useTitle('Compliance posture')
  const [view, setView] = useState<ComplianceView | null>(null)
  const [failure, setFailure] = useState<string | null>(null)

  useEffect(() => {
    let live = true
    fetchCompliance()
      .then((data) => { if (live) setView(data) })
      .catch((problem) => {
        if (!live) return
        setFailure(problem instanceof ApiError
          ? problem.message : 'Could not load the compliance posture.')
      })
    return () => { live = false }
  }, [])

  if (failure) return <p className="text-crit">{failure}</p>
  if (!view) return <p className="text-ink2">Loading…</p>

  const withFindings = view.frameworks.filter((f) => f.mapped_findings > 0)

  return (
    <>
      <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2 mb-1">
        <ScrollText size={22} className="text-accent shrink-0" />
        Compliance posture
      </h1>
      <p className="text-ink2 mb-3 max-w-[80ch]">
        {view.findings_considered} open finding
        {view.findings_considered === 1 ? '' : 's'} mapped onto{' '}
        {view.frameworks.length} control frameworks. {withFindings.length}{' '}
        {withFindings.length === 1 ? 'framework has' : 'frameworks have'} at
        least one control carrying findings.
      </p>

      {/* The caveat, once, before any number is read — not in a footnote. */}
      <div className="banner banner-warn max-w-[80ch]">
        <strong className="font-semibold">This is a gap map, not a
        certification.</strong>{' '}
        <span className="text-ink2">{view.note}</span>
      </div>

      <p className="text-[12px] text-ink3 mt-3 mb-5 max-w-[80ch]">
        Counts are of controls <strong className="text-ink2">this product
        maps</strong> — not of everything the framework contains. ISO 27001 has
        far more controls than the ones an SAP configuration export can be
        evidence about, and only those are counted here.{' '}
        <Link className="text-accent hover:underline" to="/csf">
          NIST CSF has its own screen →
        </Link>
      </p>

      <div className="grid gap-3.5 [grid-template-columns:repeat(auto-fit,minmax(440px,1fr))]">
        {view.frameworks.map((f) => (
          <Framework key={f.id} framework={f} />
        ))}
      </div>
    </>
  )
}
