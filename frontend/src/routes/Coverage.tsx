import { useEffect, useState } from 'react'
import { ApiError, coverage } from '../api/client'
import type { Coverage as CoverageView, Severity } from '../api/types'
import { useTitle } from '../lib/title'
import { CheckRefs, RequirementRef } from '../components/Refs'
import { Meter } from '../components/Meter'
import { ShieldCheck } from 'lucide-react'
import { CARD_TITLE as CARD_H3, KPI, KPI_NOTE } from '../lib/ui'

/**
 * The published check catalogue and its coverage of SAP's own Security Baseline —
 * ported from server/templates/coverage.html.
 *
 * THIS IS THE HONESTY SCREEN, NOT A SCORE. It exists to say what was NOT assessed
 * and why, and the "not covered" table is the part that earns it: publishing the
 * catalogue is the cheapest differentiator available, because the incumbents
 * assert check counts and publish no catalogue at all — 300-odd auditable checks
 * beat an unverifiable larger number, but only if the honest gaps are published
 * alongside them.
 *
 * SO IT IS DELIBERATELY NOT A PASS/FAIL DASHBOARD. There is no overall percentage
 * and no traffic light, because a single number invites exactly the reading the
 * screen exists to prevent: three separate counts — covered, beyond, not covered —
 * with the uncovered families listed by name and the reason for the biggest group
 * (NetWeaver Java, a deliberate scope decision) stated on the page.
 *
 * COVERAGE IS COMPUTED SERVER-SIDE from the check ids actually in the catalogue,
 * so the page cannot drift from what the scanner really does. Nothing here counts
 * anything the API did not already count.
 */

/** SAP's requirement tiers borrow the severity palette so the eye reads urgency
 *  the same way it does everywhere else in the console. CRITICAL is SAP's own
 *  word; STANDARD is their baseline expectation and takes HIGH; anything else
 *  named takes LOW, and an untiered requirement is INFO. */
function tierSeverity(tier: string | null): Severity {
  if (tier === 'CRITICAL') return 'CRITICAL'
  if (tier === 'STANDARD') return 'HIGH'
  return tier ? 'LOW' : 'INFO'
}

/** `meta` is the catalogue's own provenance block, typed Record<string, unknown>
 *  because it is read straight out of the content JSON. A coverage percentage
 *  without its provenance is a claim an auditor cannot check, so the values are
 *  narrowed and rendered rather than assumed present. */
function str(v: unknown): string | null {
  return typeof v === 'string' && v !== '' ? v : null
}

const CARD = 'rounded-lg border border-cardline bg-panel p-4'
const G4 = 'grid gap-3.5 [grid-template-columns:repeat(auto-fit,minmax(210px,1fr))]'
const H2 = 'text-[15px] font-semibold text-ink mt-7 mb-2.5'
const TH = 'text-left text-[11px] font-semibold uppercase tracking-[.05em] text-ink3 px-2.5 py-2 border-b border-line'
const TD = 'px-2.5 py-2.5 border-b border-line align-top'
const TABLE_CARD = 'rounded-lg border border-cardline bg-panel overflow-x-auto'
const EMPTY = 'p-9 text-center text-ink2'

export function Coverage() {
  useTitle('Coverage')
  const [cov, setCov] = useState<CoverageView | null>(null)
  const [failure, setFailure] = useState<string | null>(null)

  useEffect(() => {
    let live = true
    coverage()
      .then((c) => { if (live) setCov(c) })
      .catch((e: unknown) => {
        if (!live) return
        const status = e instanceof ApiError ? e.status : 0
        setFailure(status === 403
          ? 'Your account is not permitted to see the check catalogue.'
          : `The check catalogue could not be loaded${status ? ` (HTTP ${status})` : ''}.`)
      })
    return () => { live = false }
  }, [])

  return (
    <>
      <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2 mb-1">
        <ShieldCheck size={22} className="text-accent shrink-0" />
        Check Catalogue and Control Coverage
      </h1>
      <p className="text-ink2 mb-5">
        What this tool checks, and how it lines up against SAP&rsquo;s own published
        Security Baseline requirements.
      </p>

      {failure && <div className="banner banner-bad">{failure}</div>}
      {!failure && cov === null && <p className="text-[13px] text-ink3">Loading…</p>}
      {cov !== null && <Body cov={cov} />}
    </>
  )
}

function Body({ cov }: { cov: CoverageView }) {
  const meta = cov.meta

  return (
    <>
      <div className="banner banner-info">
        <strong className="font-[650]">Published in full, including the gaps.</strong>{' '}
        Coverage is measured against requirement families parsed from SAP&rsquo;s own
        Apache-2.0 policy files, not against a number we chose.
        {cov.note && <><br /><span className="text-[12px]">{cov.note}</span></>}
      </div>

      <div className={G4}>
        <div className={CARD}>
          <h3 className={CARD_H3}>Our checks</h3>
          <div className={KPI}>{cov.our_checks}</div>
          {/* "emitted on the reference dataset" described the OLD number, which
              came from check_definition — a table written only when a check
              produces a finding. It fell as a customer's posture improved. This
              one is read from the scanner's own source and never moves. */}
          <div className={KPI_NOTE}>
            written into the scanner
            {typeof cov.observed_checks === 'number' && (
              <> &middot; {cov.observed_checks} have produced a finding here</>
            )}
          </div>
        </div>
        <div className={CARD}>
          <h3 className={CARD_H3}>SAP requirements covered</h3>
          {/* A meter, not a donut. This is one value against a ceiling and the
              ceiling is the point; a covered-vs-uncovered pie would turn the
              denominator into a second slice, which reads as though "not
              covered" were something the product produces rather than the room
              left in SAP's list.

              Neutral rather than a traffic light on purpose: the Baseline covers
              a narrow set and most of what this product checks lies outside it,
              so colouring the empty part red would be a claim the number does
              not support. */}
          <Meter value={cov.requirements_covered}
                 limit={cov.requirements_published}
                 label="families"
                 note={`Baseline ${cov.baseline_version ?? '—'}`} />
        </div>
        <div className={CARD}>
          <h3 className={CARD_H3}>Beyond the Baseline</h3>
          <div className={`${KPI} text-ok`}>{cov.beyond_baseline.length}</div>
          <div className={KPI_NOTE}>SoD, GRC, financial controls, risk paths</div>
        </div>
        <div className={CARD}>
          <h3 className={CARD_H3}>Not covered</h3>
          <div className={`${KPI} text-high`}>{cov.not_covered.length}</div>
          <div className={KPI_NOTE}>stated, not hidden</div>
        </div>
      </div>

      <h2 className={H2}>SAP Baseline requirements we address</h2>
      <div className={TABLE_CARD}>
        <table className="w-full border-collapse">
          <thead>
            <tr>
              <th className={`${TH} w-[110px]`}>Requirement</th>
              <th className={`${TH} w-[92px]`}>Tier</th>
              <th className={`${TH} w-[76px]`}>Stack</th>
              <th className={TH}>SAP&rsquo;s description</th>
              <th className={`${TH} w-[30%]`}>Our checks</th>
            </tr>
          </thead>
          <tbody>
            {cov.covered.map((r) => (
              <tr key={r.requirement} className="hover:bg-panel2">
                <td className={`${TD} font-mono text-[12px]`}>
                  <RequirementRef id={r.requirement} />
                </td>
                <td className={TD}>
                  <span className={`pill sev-${tierSeverity(r.tier)}`}>
                    {r.tier || 'untiered'}
                  </span>
                </td>
                <td className={`${TD} text-[12px] text-ink2`}>{r.technology}</td>
                <td className={`${TD} text-[12px]`}>{r.title}</td>
                {/* Six ids and a count, not the whole list: a requirement family can
                    map to thirty checks and the column is a sample, not the index.
                    The sampling survives the ids becoming links — CheckRefs takes
                    the same limit and renders the same `+N`. */}
                <td className={`${TD} text-[12px]`}>
                  <CheckRefs ids={r.our_checks} limit={6} separator=", " />
                </td>
              </tr>
            ))}
            {cov.covered.length === 0 && (
              <tr>
                <td className={EMPTY} colSpan={5}>
                  No Baseline requirement family is currently mapped to a check.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <h2 className={H2}>SAP Baseline requirements we do not address</h2>
      {/* Publishing this is the point. A coverage page that only lists what you cover
          is marketing; one that lists what you do not is evidence. */}
      <div className="banner banner-warn">
        Most of these are <strong className="font-[650]">NetWeaver Java</strong>, which
        this tool does not cover — a deliberate scope decision, not an oversight. The rest
        are listed so nobody has to discover them in a proof of concept.
      </div>
      <div className={TABLE_CARD}>
        <table className="w-full border-collapse">
          <thead>
            <tr>
              <th className={`${TH} w-[110px]`}>Requirement</th>
              <th className={`${TH} w-[92px]`}>Tier</th>
              <th className={`${TH} w-[76px]`}>Stack</th>
              <th className={TH}>SAP&rsquo;s description</th>
            </tr>
          </thead>
          <tbody>
            {cov.not_covered.map((r) => (
              <tr key={r.requirement} className="hover:bg-panel2">
                {/* Linked even though we do not answer it: the page says so, and
                    "what does this require, and why don't we do it" is a fair
                    question to be able to click on. */}
                <td className={`${TD} font-mono text-[12px]`}>
                  <RequirementRef id={r.requirement} />
                </td>
                <td className={TD}>
                  <span className={`pill sev-${tierSeverity(r.tier)}`}>
                    {r.tier || 'untiered'}
                  </span>
                </td>
                <td className={`${TD} text-[12px] text-ink2`}>{r.technology}</td>
                <td className={`${TD} text-[12px]`}>{r.title}</td>
              </tr>
            ))}
            {cov.not_covered.length === 0 && (
              <tr>
                <td className={EMPTY} colSpan={4}>
                  Every requirement family published in this Baseline version maps to at
                  least one check.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <h2 className={H2}>Checks that go beyond the Baseline</h2>
      <p className="text-ink2 text-[12px] mb-2.5">
        {cov.beyond_baseline.length} checks map to no SAP Baseline requirement. That is not
        a failure — permission-level Segregation of Duties, GRC access governance, SOX
        financial configuration and the attack-path content have no Baseline equivalent,
        and they are where this tool goes past it.
      </p>
      <div className={CARD}>
        <p className="font-mono text-[12px] text-ink3 m-0 leading-[1.9]">
          {cov.beyond_baseline.join(' · ')}
        </p>
      </div>

      <div className={`${CARD} mt-[18px]`}>
        <h3 className={CARD_H3}>Source and licence</h3>
        <dl className="grid [grid-template-columns:auto_1fr] gap-x-4 gap-y-1.5 m-0">
          <dt className="text-ink3 text-[12px]">Requirement source</dt>
          <dd className="m-0 text-[12px]">{str(meta.source) ?? '—'}</dd>
          <dt className="text-ink3 text-[12px]">Licence</dt>
          <dd className="m-0 text-[12px]">{str(meta.licence) ?? '—'}</dd>
          <dt className="text-ink3 text-[12px]">Baseline version</dt>
          <dd className="m-0 text-[12px] font-mono">{str(meta.baseline_version) ?? '—'}</dd>
          <dt className="text-ink3 text-[12px]">Derivation</dt>
          <dd className="m-0 text-[12px] text-ink2">{str(meta.note) ?? '—'}</dd>
        </dl>
      </div>
    </>
  )
}
