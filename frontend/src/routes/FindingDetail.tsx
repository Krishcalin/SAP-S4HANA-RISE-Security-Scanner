/*
 * Copyright (c) 2026 Krishnendu De. All Rights Reserved.
 *
 * Author : Krishnendu De
 * Coding Assistance : Claude Code
 * Code Security Assistance : Code QL
 */

import { useEffect, useState, type FormEvent } from 'react'
import { Link, useParams } from 'react-router'
import {
  ApiError, assignFinding, finding as fetchFinding, findingHistory, setFindingState,
} from '../api/client'
import type { FindingDetail as Finding, FindingHistory } from '../api/types'
import { useSession } from '../lib/session'
import { useTitle } from '../lib/title'
import { CheckRef } from '../components/Refs'
import { CircleAlert } from 'lucide-react'
import { CARD_TITLE } from '../lib/ui'

/**
 * One finding in full — ported from server/templates/finding_detail.html.
 *
 * THE REMEDIATION IS A LIST, NOT A PARAGRAPH. The knowledge base authors a
 * procedure as one numbered step per line separated by a single newline, and HTML
 * collapses newlines to spaces: dropped into a <p>, a ten-step procedure becomes
 * a wall of text nobody can work down and in which nobody can say "I'm on step
 * 4". `steps()` below is server/prose.py ported line for line, including its
 * refusal to renumber — read that module before changing either copy.
 *
 * THE OWNERSHIP BANNER IS THE POINT OF THE SCREEN. In RISE a customer can SEE a
 * bad profile parameter and cannot fix it. Telling them to "change this setting"
 * would be unactionable noise, so a provider-owned finding renders as a service
 * request with the text pre-drafted instead.
 */
export function FindingDetail() {
  const { user } = useSession()
  const { id } = useParams<{ id: string }>()
  const findingId = Number(id)

  const [finding, setFinding] = useState<Finding | null>(null)
  const [trail, setTrail] = useState<FindingHistory | null>(null)
  const [error, setError] = useState('')
  const [reloads, setReloads] = useState(0)

  // The CHECK ID, as finding_detail.html's `{% block title %}` does — not the
  // title, which is a sentence and would be truncated to nothing useful in a tab
  // strip. null until it loads, so the queue's title stays up rather than
  // blinking through a placeholder.
  useTitle(finding?.check_id ?? null)

  useEffect(() => {
    if (!Number.isInteger(findingId)) { setError('That is not a finding id.'); return }
    let cancelled = false
    setError('')
    // Two calls rather than one: the lifecycle trail and the per-run observations
    // are a second query the server keeps separate, and the detail renders without
    // them if that one fails.
    Promise.all([fetchFinding(findingId), findingHistory(findingId)])
      .then(([f, h]) => { if (!cancelled) { setFinding(f); setTrail(h) } })
      .catch((e) => { if (!cancelled) { setError(describe(e)); setFinding(null) } })
    return () => { cancelled = true }
  }, [findingId, reloads])

  if (error) {
    return (
      <>
        <p className="text-[12px] mb-4">
          <Link className="text-accent" to="/findings">← Findings</Link>
        </p>
        <div className="banner banner-bad" role="alert">{error}</div>
      </>
    )
  }
  if (!finding) return <p className="text-ink3 text-[13px]">Loading…</p>

  const details = obj(finding.latest_details) ?? {}
  const isCode = ['abap_scan', 'atc_export'].includes(str(details['source']))
  const remediationSteps = steps(finding.remediation)

  // `expired_acceptance` is computed by the LIST query and is not on this row —
  // the template checks a field the single-finding query never selects, so its
  // banner has never once fired. Derived here from the two columns that do come
  // back, because "the time-box has passed" is the whole reason the state is
  // shown at all.
  const acceptanceExpired = finding.state === 'accepted' &&
    finding.acceptance_due !== null && finding.acceptance_due < today()

  return (
    <>
      <p className="text-[12px] mb-4">
        <Link className="text-accent" to="/findings">← Findings</Link>
      </p>

      <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2 mb-1">
        <CircleAlert size={22} className="text-accent shrink-0" />
        <span className={`pill sev-${finding.severity ?? 'INFO'} mr-2 align-middle`}>
          {finding.severity ?? 'INFO'}
        </span>
        {finding.title}
      </h1>
      <p className="text-ink2 mb-5">
        {/* The one place a finding links to its DEFINITION. Doing it here,
            once, rather than from every row that names the check, is what keeps
            the triage queue's own links pointing at the defect a reader clicked. */}
        <CheckRef id={finding.check_id} />
        {finding.system_label && <> · <span className="font-mono">{finding.system_label}</span></>}
        {finding.baseline_req_id && (
          <> · SAP Security Baseline <span className="font-mono">{finding.baseline_req_id}</span></>
        )}
      </p>

      {finding.remediation_owner === 'ticket_to_sap' && (
        <div className="banner banner-info">
          <strong className="font-semibold">This is SAP&rsquo;s to change.</strong> Under{' '}
          {finding.deployment_mode}, the setting is operated by the provider. Raise a
          service request rather than attempting the change — the pre-drafted text is
          below.
          {finding.provider_ticket_ref && (
            <> Submitted as <span className="font-mono">{finding.provider_ticket_ref}</span>.</>
          )}
        </div>
      )}
      {finding.remediation_owner === 'provider_owned' && (
        <div className="banner">
          <strong className="font-semibold">No customer action.</strong> Shown for
          completeness and for your auditor.
        </div>
      )}
      {finding.remediation_owner === 'not_assessable' && (
        <div className="banner banner-warn">
          <strong className="font-semibold">Out of reach in RISE.</strong> This check
          needs OS-level access, which RISE customers contractually do not have. It is
          listed so the coverage map stays honest, and it is excluded from the score.
        </div>
      )}

      {acceptanceExpired && (
        <div className="banner banner-bad">
          <strong className="font-semibold">Risk acceptance expired</strong> on{' '}
          {finding.acceptance_due}. The defect is open and the time-box has passed.
        </div>
      )}

      <div className={G2}>
        <div className={CARD}>
          <h3 className={CARD_TITLE}>Status</h3>
          <dl className={KV}>
            <dt className={DT}>State</dt>
            <dd className={DD}>
              <span className={`pill st st-${finding.state}`}>
                {finding.state.replace(/_/g, ' ')}
              </span>
            </dd>
            <dt className={DT}>Ownership</dt>
            <dd className={DD}>
              <span className={`own own-${finding.remediation_owner}`}>
                {finding.remediation_owner.replace(/_/g, ' ')}
              </span>
            </dd>
            <dt className={DT}>Responsibility</dt>
            <dd className={`${DD} text-ink2`}>{finding.responsibility ?? 'unknown'}</dd>
            <dt className={DT}>Assignee</dt><dd className={DD}>{finding.assignee ?? '—'}</dd>
            <dt className={DT}>Team</dt><dd className={DD}>{finding.owning_team ?? '—'}</dd>
            <dt className={DT}>Due</dt><dd className={DD}>{finding.due_date ?? '—'}</dd>
            <dt className={DT}>First seen</dt>
            <dd className={DD}>{fmtDate(finding.first_seen_at)}</dd>
            <dt className={DT}>Last detected</dt>
            <dd className={DD}>{fmtDate(finding.last_detected_at)}</dd>
            {finding.regression_count > 0 && (
              <>
                <dt className={DT}>Regressions</dt>
                <dd className={`${DD} text-high`}>{finding.regression_count}</dd>
              </>
            )}
          </dl>
        </div>

        <div className={CARD}>
          <h3 className={CARD_TITLE}>Identity</h3>
          {/* Stored, not inferred. A journey feature that cannot explain why two
              findings did or did not match across runs is not trustworthy. */}
          <dl className={KV}>
            <dt className={DT}>Matched by</dt>
            <dd className={DD}>
              {finding.fingerprint_basis}
              <div className="text-[12px] text-ink3 mt-0.5">
                {finding.fingerprint_basis === 'objects' &&
                  'Structural — identity comes from the named SAP objects and survives rewording.'}
                {finding.fingerprint_basis === 'display' &&
                  "Derived from display text. Stable while this check's wording is stable."}
                {finding.fingerprint_basis === 'check_only' &&
                  'Aggregate — identified by check and system. Correctly coarse: its members change between runs without resetting its age.'}
              </div>
            </dd>
            <dt className={DT}>Scope</dt><dd className={DD}>{finding.scope}</dd>
            <dt className={DT}>Fingerprint</dt>
            <dd className={`${DD} font-mono text-[12px] text-ink3`}>
              {finding.fingerprint.slice(0, 32)}…
            </dd>
          </dl>

          {finding.subject.length > 0 && (
            <>
              <h3 className={`${CARD_TITLE} mt-3.5`}>Affected objects</h3>
              <table className="w-full border-collapse">
                <tbody>
                  {finding.subject.map((raw, i) => {
                    const o = obj(raw) ?? {}
                    return (
                      <tr key={i} className="hover:bg-panel2">
                        <td className={`${TD} text-[12px] text-ink3 w-[120px]`}>
                          {str(o['type'])}
                        </td>
                        <td className={`${TD} font-mono text-[12px]`}>
                          {str(o['name'])}
                          {str(o['qualifier']) && (
                            <span className="text-ink3"> · {str(o['qualifier'])}</span>
                          )}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </>
          )}
        </div>
      </div>

      {/* A code finding is unusable without the code. `latest_details` is the
          newest observation's jsonb: the snippet and the taint trace are what the
          source looked like in THAT run, which is why they are not columns on the
          finding. */}
      {isCode && (
        <>
          <h2 className={H2}>Code location</h2>
          <div className={CARD}>
            <dl className={KV}>
              {str(details['file']) && (
                <>
                  <dt className={DT}>File</dt>
                  <dd className={`${DD} font-mono text-[12px]`}>{str(details['file'])}</dd>
                </>
              )}
              {arr(details['lines']).length > 0 && (
                <>
                  <dt className={DT}>Line{arr(details['lines']).length > 1 ? 's' : ''}</dt>
                  <dd className={`${DD} font-mono text-[12px]`}>
                    {arr(details['lines']).slice(0, 20).map((l) => String(l)).join(', ')}
                    {arr(details['lines']).length > 20 && (
                      <span className="text-ink3"> +{arr(details['lines']).length - 20} more</span>
                    )}
                  </dd>
                </>
              )}
              {num(details['occurrences']) !== null && (
                <>
                  <dt className={DT}>Occurrences</dt>
                  <dd className={DD}>{num(details['occurrences'])}</dd>
                </>
              )}
              {finding.cwe && (
                <>
                  <dt className={DT}>CWE</dt>
                  <dd className={`${DD} font-mono text-[12px]`}>{finding.cwe}</dd>
                </>
              )}

              <dt className={DT}>Evidence</dt>
              <dd className={DD}>
                {str(details['evidence']) === 'sap_atc' ? (
                  // Not our finding. Saying so is the difference between "SAP found
                  // this" and "our pattern matched", and a reviewer weighs them
                  // differently.
                  <>
                    <span className="pill st st-resolved">SAP ATC / CVA</span>{' '}
                    <span className="text-[12px] text-ink3">reported by SAP&rsquo;s own engine</span>
                  </>
                ) : finding.taint_confidence === 'confirmed' ? (
                  <>
                    <span className="pill sev-CRITICAL">data-flow confirmed</span>{' '}
                    <span className="text-[12px] text-ink3">
                      tainted input provably reaches this statement
                    </span>
                  </>
                ) : finding.taint_confidence === 'tentative' ? (
                  <>
                    <span className="pill sev-MEDIUM">tentative</span>{' '}
                    <span className="text-[12px] text-ink3">
                      the data-flow walk found no evidence either way
                    </span>
                  </>
                ) : (
                  <>
                    <span className="pill st">pattern only</span>{' '}
                    <span className="text-[12px] text-ink3">
                      matched by statement pattern; no data-flow evidence
                    </span>
                  </>
                )}
              </dd>

              {finding.reachability && (
                <>
                  <dt className={DT}>Reachable</dt>
                  <dd className={DD}>
                    {finding.reachability === 'reachable' &&
                      <span className="own own-ticket_to_sap">reachable</span>}
                    {finding.reachability === 'unreachable' &&
                      <span className="own own-provider_owned">no path found</span>}
                    {finding.reachability !== 'reachable' && finding.reachability !== 'unreachable' &&
                      <span className="own own-not_assessable">unknown</span>}
                    {arr(details['reachability_reasons']).length > 0 && (
                      <div className="text-[12px] text-ink3 mt-1">
                        {arr(details['reachability_reasons']).map((r) => String(r)).join(' · ')}
                      </div>
                    )}
                    {finding.reachability === 'unknown' && (
                      <div className="text-[12px] text-ink3 mt-1">
                        Supply <span className="font-mono">REFERENCED</span> /{' '}
                        <span className="font-mono">LAST_USED</span> in{' '}
                        <span className="font-mono">code_inventory.csv</span> to rank this
                        against the rest of the custom code.
                      </div>
                    )}
                  </dd>
                </>
              )}
            </dl>

            {str(details['snippet']) && (
              <>
                <h3 className={`${CARD_TITLE} mt-[18px]`}>Source</h3>
                <pre className="font-mono text-[12px] whitespace-pre overflow-x-auto bg-panel2 p-3 rounded-md m-0">
                  {str(details['snippet'])}
                </pre>
              </>
            )}

            {arr(details['taint_flow']).length > 0 && (
              <>
                {/* The best thing this engine produces, and there is nothing else
                    like it in the product: the actual path from the untrusted
                    source to the dangerous sink. */}
                <h3 className={`${CARD_TITLE} mt-[18px]`}>How untrusted input reaches it</h3>
                <div className="overflow-x-auto">
                  <table className="w-full border-collapse">
                    <thead>
                      <tr>
                        <th className={`${TH} w-[70px]`}>Line</th>
                        <th className={`${TH} w-[90px]`}>Role</th>
                        <th className={`${TH} w-[130px]`}>Variable</th>
                        <th className={TH}>Statement</th>
                      </tr>
                    </thead>
                    <tbody>
                      {arr(details['taint_flow']).map((raw, i) => {
                        const hop = obj(raw) ?? {}
                        const role = str(hop['role'])
                        return (
                          <tr key={i} className="hover:bg-panel2">
                            <td className={`${TD} font-mono text-[12px]`}>{str(hop['line'])}</td>
                            <td className={TD}>
                              {role === 'source' ? <span className="pill sev-HIGH">source</span>
                                : role === 'sink' ? <span className="pill sev-CRITICAL">sink</span>
                                : <span className="pill st">{role}</span>}
                            </td>
                            <td className={`${TD} font-mono text-[12px]`}>{str(hop['var'])}</td>
                            <td className={`${TD} font-mono text-[12px]`}>{str(hop['code'])}</td>
                          </tr>
                        )
                      })}
                    </tbody>
                  </table>
                </div>
              </>
            )}

            {details['suppressed_by_source_marker'] === true && (
              <div className="banner banner-warn mt-3.5 mb-0">
                <strong className="font-semibold">
                  Suppressed in source by a #NOSEC marker.
                </strong>{' '}
                It is reported anyway: a suppression that leaves no record is
                indistinguishable from clean code. If the claim is right, dismiss it here
                instead — that decision is attributed, expires and can be reviewed.
              </div>
            )}

            {details['also_reported_by_atc'] === true && (
              <div className="banner banner-info mt-3.5 mb-0">
                SAP&rsquo;s ATC also reports a finding on this object. Both are kept: they
                are independent evidence for the same defect.
              </div>
            )}
          </div>
        </>
      )}

      <h2 className={H2}>Risk</h2>
      {/* Authored one paragraph per line. Inside a single <p> the browser collapses
          every newline to a space and the reader gets a wall of text. */}
      <div className={CARD}>
        {paragraphs(finding.risk_narrative).map((para, i) => (
          <p key={i} className="mb-2.5 last:mb-0">{para}</p>
        ))}
        {paragraphs(finding.risk_narrative).length === 0 && (
          <p className="text-ink3 m-0">No risk narrative is authored for this check.</p>
        )}
      </div>

      <h2 className={H2}>Remediation</h2>
      <div className={CARD}>
        {/* A numbered procedure is a list, so it is marked up as one: the steps get
            hanging indentation, and a screen reader announces "list, N items"
            instead of reading a paragraph. `steps()` returns null when the text is
            not a clean 1..N run — an <ol> would silently renumber it — and the text
            then renders exactly as written. */}
        {remediationSteps ? (
          <ol className="m-0 pl-[1.6em] list-decimal marker:text-ink3 marker:tabular-nums">
            {remediationSteps.map((step, i) => (
              <li key={i} className="mb-2 pl-0.5 last:mb-0">{step}</li>
            ))}
          </ol>
        ) : (
          paragraphs(finding.remediation).map((para, i) => (
            <p key={i} className="mb-2.5 last:mb-0">{para}</p>
          ))
        )}
        {paragraphs(finding.remediation).length === 0 && (
          <p className="text-ink3 m-0">No remediation is authored for this check.</p>
        )}

        {finding.remediation_owner === 'ticket_to_sap' && (
          <>
            <h3 className={`${CARD_TITLE} mt-[18px]`}>Service request text</h3>
            <pre className="font-mono text-[12px] whitespace-pre-wrap bg-panel2 p-3 rounded-md m-0">
{`System: ${finding.system_label ?? '(not recorded)'}
Check:  ${finding.check_id} — ${finding.title}
Request: apply the target configuration described below.
Reference: ${finding.baseline_req_id ?? 'SAP Security Baseline'}

${finding.remediation ?? ''}`}
            </pre>
          </>
        )}
      </div>

      {finding.references_json.length > 0 && (
        <>
          <h2 className={H2}>References</h2>
          <div className={CARD}>
            <ul className="m-0 pl-[18px] list-disc">
              {finding.references_json.map((ref, i) => (
                <li key={i} className="text-[12px]">{String(ref)}</li>
              ))}
            </ul>
          </div>
        </>
      )}

      <h2 className={H2}>History</h2>
      <div className={`${CARD} p-0 overflow-x-auto`}>
        <table className="w-full border-collapse">
          <thead>
            <tr>
              <th className={`${TH} w-[150px]`}>When</th>
              <th className={`${TH} w-[200px]`}>Change</th>
              <th className={`${TH} w-[110px]`}>By</th>
              <th className={TH}>Reason</th>
            </tr>
          </thead>
          <tbody>
            {(trail?.history ?? []).map((t) => (
              <tr key={t.id} className="hover:bg-panel2">
                <td className={`${TD} text-[12px] text-ink2`}>{fmtDateTime(t.occurred_at)}</td>
                <td className={`${TD} text-[12px]`}>
                  {t.from_state ?? '—'} → <strong className="font-semibold">{t.to_state}</strong>
                </td>
                <td className={`${TD} text-[12px]`}>{t.actor}</td>
                <td className={`${TD} text-[12px] text-ink2`}>{t.reason ?? ''}</td>
              </tr>
            ))}
            {trail && trail.history.length === 0 && (
              <tr>
                <td colSpan={4} className={EMPTY}>
                  Nobody has moved this finding. It is where the scanner left it.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <h2 className={H2}>Observed in</h2>
      <div className={`${CARD} p-0 overflow-x-auto`}>
        <table className="w-full border-collapse">
          <thead>
            <tr>
              <th className={`${TH} w-[150px]`}>Run</th>
              <th className={`${TH} w-[90px]`}>Severity</th>
              <th className={`${TH} w-[80px] text-right`}>Items</th>
              <th className={TH}>Members</th>
            </tr>
          </thead>
          <tbody>
            {(trail?.observations ?? []).map((o) => (
              <tr key={o.id} className="hover:bg-panel2">
                <td className={`${TD} text-[12px]`}>
                  <Link className="text-accent" to={`/runs/${o.scan_run_id}`}>
                    #{o.scan_run_id}
                  </Link>{' '}
                  <span className="text-ink3">{fmtDate(o.started_at)}</span>
                </td>
                <td className={TD}>
                  <span className={`pill sev-${o.severity ?? 'INFO'}`}>{o.severity}</span>
                </td>
                <td className={`${TD} text-right font-mono text-[12px]`}>{o.affected_count}</td>
                <td className={`${TD} text-[12px] text-ink2`}>
                  {o.affected_items.slice(0, 6).map((x) => String(x)).join(', ')}
                  {o.affected_items.length > 6 ? ' …' : ''}
                </td>
              </tr>
            ))}
            {trail && trail.observations.length === 0 && (
              <tr><td colSpan={4} className={EMPTY}>No observations recorded.</td></tr>
            )}
          </tbody>
        </table>
      </div>

      {user.can_write && (
        <Actions findingId={finding.id} onDone={() => setReloads((n) => n + 1)} />
      )}
    </>
  )
}

// ── the two writes ───────────────────────────────────────────────────────────

/**
 * Move it, or hand it to somebody.
 *
 * THE RULES ARE THE SERVER'S. A reason is required to accept or dispute, a ticket
 * to submit to SAP, and the transition table decides the rest. None of that is
 * re-implemented here: a client-side copy drifts from `queries.ALLOWED_TRANSITIONS`
 * and the drift shows up as a form refusing a move the API would have allowed.
 * The 400's message is surfaced as written.
 *
 * `resolved` is not offered. It is set by the SCANNER not observing the finding
 * again, never by a person clicking a button — that is what makes the resolved
 * count mean anything.
 */
function Actions({ findingId, onDone }: { findingId: number; onDone: () => void }) {
  const [state, setState] = useState('submitted_to_provider')
  const [reason, setReason] = useState('')
  const [ticket, setTicket] = useState('')
  const [assignee, setAssignee] = useState('')
  const [team, setTeam] = useState('')
  const [due, setDue] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [done, setDoneMessage] = useState('')

  async function move(e: FormEvent) {
    e.preventDefault()
    setBusy(true); setError(''); setDoneMessage('')
    try {
      const result = await setFindingState(findingId, state, reason, ticket)
      setDoneMessage(`Moved ${result.from} → ${result.to}.`)
      onDone()
    } catch (err) {
      setError(describe(err))
    } finally {
      setBusy(false)
    }
  }

  async function assign(e: FormEvent) {
    e.preventDefault()
    setBusy(true); setError(''); setDoneMessage('')
    try {
      const result = await assignFinding(findingId, assignee || undefined,
                                         team || undefined, due || undefined)
      setDoneMessage(result.changed ? 'Assignment updated.' : 'Nothing to change.')
      onDone()
    } catch (err) {
      setError(describe(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <h2 className={H2}>Update</h2>
      {error && <div className="banner banner-bad" role="alert">{error}</div>}
      {done && <div className="banner banner-ok">{done}</div>}

      <form onSubmit={move} className={`${CARD} flex gap-2 flex-wrap items-end max-w-[820px]`}>
        <div>
          <label className={LABEL}>Move to</label>
          <select className="field mt-1" value={state} onChange={(e) => setState(e.target.value)}>
            {MOVES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </select>
        </div>
        <div className="flex-1 min-w-[220px]">
          <label className={LABEL}>Reason (required to accept or dispute)</label>
          <input className="field mt-1" value={reason} onChange={(e) => setReason(e.target.value)} />
        </div>
        <div>
          <label className={LABEL}>SAP ticket</label>
          <input className="field mt-1" placeholder="e.g. 1234567890" value={ticket}
                 onChange={(e) => setTicket(e.target.value)} />
        </div>
        <button type="submit" className="btn" disabled={busy}>Apply</button>
      </form>

      {/* Assigning is deliberately NOT a transition: a finding can change hands
          three times while staying open, and recording that in the lifecycle trail
          would fill it with entries that say nothing about the defect. */}
      <form onSubmit={assign}
            className={`${CARD} mt-3 flex gap-2 flex-wrap items-end max-w-[820px]`}>
        <div>
          <label className={LABEL}>Assignee</label>
          <input className="field mt-1" value={assignee}
                 onChange={(e) => setAssignee(e.target.value)} />
        </div>
        <div>
          <label className={LABEL}>Team</label>
          <select className="field mt-1" value={team} onChange={(e) => setTeam(e.target.value)}>
            <option value="">—</option>
            {TEAMS.map((t) => <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>)}
          </select>
        </div>
        <div>
          <label className={LABEL}>Due date</label>
          <input className="field mt-1" type="date" value={due}
                 onChange={(e) => setDue(e.target.value)} />
        </div>
        <button type="submit" className="btn btn-ghost" disabled={busy}>Assign</button>
        <span className="basis-full text-[12px] text-ink3">
          A field left blank is left unchanged, and none of this touches the state.
        </span>
      </form>
    </>
  )
}

// ── authored text ────────────────────────────────────────────────────────────
// server/prose.py, ported. Both consoles render the same corpus and must reach the
// same decision about it, so this is a transcription rather than an improvement —
// including the part that refuses.

/** "1. ", "2) ", " 10.  " — a leading ordinal and its delimiter. */
const ORDINAL = /^\s*(\d{1,3})[.)]\s+([\s\S]+)$/

/** One paragraph per non-empty line. The corpus separates paragraphs with a
 *  single newline and never with a blank line, so a blank-line split would return
 *  the whole thing as one paragraph and change nothing. */
function paragraphs(text: string | null): string[] {
  if (!text) return []
  return text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean)
}

/** The numbered steps with their ordinals stripped, or null.
 *
 *  An <ol> renumbers from 1 whatever the source said. That is fine when the
 *  source is already 1..N and actively wrong otherwise: text numbered 3,4,5 (an
 *  excerpt) or 1,2,2,3 (an authoring slip) would be silently RENUMBERED and the
 *  rendered numbers would no longer match what the text refers to. So a wrong
 *  ordinal aborts and the caller falls back to paragraphs, which preserve the
 *  text as written. An UNNUMBERED line is a hard-wrapped continuation of the step
 *  before it. */
function steps(text: string | null): string[] | null {
  const lines = paragraphs(text)
  if (lines.length < 2) return null

  const out: string[] = []
  let expected = 1
  for (const line of lines) {
    const match = ORDINAL.exec(line)
    if (match) {
      if (Number(match[1]) !== expected) return null    // 1,2,2 or 1,2,4
      out.push(match[2].trim())
      expected += 1
    } else if (out.length) {
      out[out.length - 1] = `${out[out.length - 1]} ${line}`
    } else {
      return null                                        // does not begin at step 1
    }
  }
  return out.length >= 2 ? out : null
}

// ── plumbing ─────────────────────────────────────────────────────────────────

/** 'YYYY-MM-DD'. A date-only value is already in that shape and must NOT go
 *  through `Date`: ISO date-only parses as UTC midnight and renders as the
 *  previous day west of Greenwich. */
function fmtDate(value: string | null): string {
  if (!value) return '—'
  if (/^\d{4}-\d{2}-\d{2}$/.test(value)) return value
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return value
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`
}

function fmtDateTime(value: string | null): string {
  if (!value) return '—'
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return value
  const p = (n: number) => String(n).padStart(2, '0')
  return `${fmtDate(value)} ${p(d.getHours())}:${p(d.getMinutes())}`
}

/** Local calendar date as 'YYYY-MM-DD' — comparable with `acceptance_due`, which
 *  the server sends as a bare date. */
function today(): string {
  const d = new Date()
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`
}

// jsonb arrives as `unknown`; these narrow one level at a time so a shape change
// in the scanner degrades to a blank cell instead of throwing on render.
function obj(v: unknown): Record<string, unknown> | null {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
    ? (v as Record<string, unknown>) : null
}
function arr(v: unknown): unknown[] {
  return Array.isArray(v) ? v : []
}
function num(v: unknown): number | null {
  return typeof v === 'number' && Number.isFinite(v) ? v : null
}
function str(v: unknown): string {
  return typeof v === 'string' ? v : typeof v === 'number' ? String(v) : ''
}

/** Branch on the STATUS, never on the message text. The 404 is deliberately
 *  ambiguous on the server — it does not distinguish "no such finding" from "not
 *  in your scope", because doing so would let a scoped user enumerate ids in
 *  landscapes they cannot see — and this wording keeps that property. */
function describe(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.status === 404) return 'No such finding, or it is outside the systems you can see.'
    if (e.status === 403) return 'You are not permitted to make that change.'
    if (e.status >= 500) return `The server could not answer (${e.status}).`
    return e.message
  }
  return 'The console could not reach the server.'
}

const CARD = 'rounded-lg border border-cardline bg-panel p-4'
const G2 = 'grid gap-3.5 [grid-template-columns:repeat(auto-fit,minmax(340px,1fr))]'
const H2 = 'text-[15px] font-semibold mt-[26px] mb-2.5'
const KV = 'grid [grid-template-columns:auto_1fr] gap-y-1.5 gap-x-4 m-0'
const DT = 'text-[12px] text-ink3'
const DD = 'm-0'
const TH = 'text-left px-2.5 py-2 text-[11px] font-semibold uppercase tracking-[.05em] text-ink3 border-b border-line'
const TD = 'px-2.5 py-[9px] align-top border-b border-line'
const EMPTY = 'p-9 text-center text-ink2'
const LABEL = 'block text-[12px] text-ink3'

const TEAMS = [
  'basis', 'authorizations', 'development', 'integration', 'data_protection', 'identity',
]

const MOVES: [string, string][] = [
  ['submitted_to_provider', 'Submitted to SAP'],
  ['mitigated', 'Mitigated'],
  ['accepted', 'Risk accepted'],
  ['false_positive', 'False positive'],
  ['open', 'Re-open'],
]
