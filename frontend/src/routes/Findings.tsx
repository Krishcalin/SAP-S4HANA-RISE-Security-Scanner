/*
 * Copyright (c) 2026 Krishnendu De. All Rights Reserved.
 *
 * Author : Krishnendu De
 * Coding Assistance : Claude Code
 * Code Security Assistance : Code QL
 */

import { useEffect, useState, type FormEvent } from 'react'
import { Link, useSearchParams } from 'react-router'
import {
  ApiError, assignFinding, bulkSetState, domains as fetchDomains, findings,
  saveView, systems, views,
} from '../api/client'
import type {
  BulkTransitionResult, FindingFilters, FindingPage, FindingState, PriorityTier,
  RemediationOwner, SapSystem, SavedView, SecurityDomain, Severity,
} from '../api/types'
import { useSession } from '../lib/session'
import { useTitle } from '../lib/title'
import { CircleAlert } from 'lucide-react'

/**
 * The triage queue — ported from server/templates/findings.html, and the screen
 * the product is used from.
 *
 * THE FILTERS LIVE IN THE ADDRESS BAR, NOT IN REACT STATE. Two reasons, and the
 * second one is a trap:
 *   - a filtered queue is something people send each other, and state that is not
 *     in the URL cannot be sent;
 *   - `POST /api/views` reads the filters to save off the HTTP **Referer**, not
 *     off its body ("save this view" means "save what I am looking at"). A screen
 *     holding its filters only in useState would save an EMPTY view and the
 *     failure would be silent.
 * Which is also why a filter applies on change rather than behind an Apply
 * button: a pending, unapplied selection is a filter the address bar does not
 * know about, and it would be saved wrongly by the button next to it.
 *
 * ONE ROW, ONE LINK. /findings/:id takes an id so it cannot appear in the nav
 * table; these rows are the only way to reach it.
 *
 * PARTIAL SUCCESS IS RENDERED, NOT ROUNDED OFF. `bulk-state` is deliberately not
 * all-or-nothing — the legal moves are applied and the rest come back with a
 * reason each — so both halves are shown. Reporting only the successes
 * misdescribes what happened to somebody's audit trail.
 */
export function Findings() {
  useTitle('Findings')
  const { user } = useSession()
  const [params, setParams] = useSearchParams()
  const key = params.toString()

  const [page, setPage] = useState<FindingPage | null>(null)
  const [error, setError] = useState('')
  const [reloads, setReloads] = useState(0)
  const [sapSystems, setSapSystems] = useState<SapSystem[]>([])
  const [saved, setSaved] = useState<SavedView[]>([])
  const [selected, setSelected] = useState<number[]>([])
  const [domainList, setDomainList] = useState<SecurityDomain[]>([])

  // The queue re-reads on any change to the query string, which is the whole of
  // its input. Selection is dropped with it: a checkbox for a row that is no
  // longer on screen is an instruction nobody can see.
  //
  // The previous rows are NOT cleared first. Blanking the table on every filter
  // change flashes "Loading…" between two nearly identical screens, and — worse —
  // it would unmount the bulk bar and take the outcome of the move that caused
  // the reload down with it.
  useEffect(() => {
    let cancelled = false
    setError('')
    findings(queryFrom(new URLSearchParams(key)))
      .then((p) => { if (!cancelled) { setPage(p); setSelected([]) } })
      .catch((e) => { if (!cancelled) { setError(describe(e)); setPage(null) } })
    return () => { cancelled = true }
  }, [key, reloads])

  // The filter vocabulary and the saved views are fetched once. A failure of
  // either leaves the queue itself usable, so neither raises a banner over it.
  //
  // The domain list comes from the SERVER's taxonomy rather than a constant here:
  // a hard-coded twelve would keep offering a domain the server had renamed, or
  // miss a thirteenth. The one domain this product does not assess is dropped —
  // the server refuses to filter by it, and an option that can only produce an
  // error is not a filter.
  useEffect(() => {
    let cancelled = false
    systems().then((s) => { if (!cancelled) setSapSystems(s) }).catch(() => {})
    views('findings').then((v) => { if (!cancelled) setSaved(v) }).catch(() => {})
    fetchDomains()
      .then((v) => {
        if (!cancelled) setDomainList(v.domains.filter((d) => d.reach !== 'none'))
      })
      .catch(() => {})
    return () => { cancelled = true }
  }, [])

  function setFilter(name: string, value: string) {
    const next = new URLSearchParams(params)
    if (value) next.set(name, value)
    else next.delete(name)
    // A filter change invalidates the page number — page 4 of the old result set
    // is usually past the end of the new one, which reads as "no findings".
    next.delete('page')
    setParams(next)
  }

  function goToPage(n: number) {
    const next = new URLSearchParams(params)
    next.set('page', String(n))
    setParams(next)
  }

  const rows = page?.findings ?? []
  const allSelected = rows.length > 0 && selected.length === rows.length
  const selectedDomain = domainList.find((d) => d.id === params.get('domain'))

  return (
    <>
      <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2 mb-1">
        <CircleAlert size={22} className="text-accent shrink-0" />Findings</h1>
      <p className="text-ink2 mb-5">
        {page && `${page.total} finding${page.total === 1 ? '' : 's'}. `}
        Every finding type — parameters, authorizations, SoD, HANA, BTP, code and
        transports — in one queue with one lifecycle.
      </p>

      {/* Durable, permission-scoped URLs per audience. Reporting is read access,
          not file production: a shared link re-runs under the viewer's own row
          scope, so it can never widen access. They point at /v/:slug rather than
          resolving the filters here — that screen is the one place that turns a
          slug into a query, and a second copy of the mapping would drift from it. */}
      {saved.length > 0 && (
        <div className="flex gap-2 flex-wrap items-center mb-3">
          <span className="text-[12px] text-ink3">Saved views:</span>
          {saved.map((v) => (
            <Link key={v.slug} className="btn btn-ghost no-underline"
                  to={`/v/${v.slug}`} title={v.description ?? undefined}>
              {v.name}
            </Link>
          ))}
        </div>
      )}

      <div className="flex gap-2 flex-wrap items-center mb-3.5">
        {/* First, because it is the widest cut and the one a reader arriving from
            a domain tile is already thinking in. It is absent until the list
            loads rather than rendered empty: a select offering only "Any domain"
            looks like a product with no domains. */}
        {domainList.length > 0 && (
          <Select value={params.get('domain') ?? ''}
                  onChange={(v) => setFilter('domain', v)} blank="Any domain"
                  options={domainList.map((d) => [d.id, d.label])} />
        )}
        <Select value={params.get('tier') ?? ''} onChange={(v) => setFilter('tier', v)}
                blank="Any priority" options={TIERS.map((t) => [t, t])} />
        <Select value={params.get('system_id') ?? ''}
                onChange={(v) => setFilter('system_id', v)} blank="All systems"
                options={sapSystems.map((s) => [
                  String(s.id), `${s.label} (${s.tier})`,
                ])} />
        <Select value={params.get('severity') ?? ''}
                onChange={(v) => setFilter('severity', v)} blank="Any severity"
                options={SEVERITIES.map((s) => [s, s])} />
        {/* "Open (default)" is not a no-op label: with no state filter the query
            hides resolved AND false-positive findings, which is not the same as
            state = open. */}
        <Select value={params.get('state') ?? ''} onChange={(v) => setFilter('state', v)}
                blank="Open (default)"
                options={STATES.map((s) => [s, s.replace(/_/g, ' ')])} />
        <Select value={params.get('owner') ?? ''} onChange={(v) => setFilter('owner', v)}
                blank="Any owner" options={OWNER_FILTER} />
        <Select value={params.get('team') ?? ''} onChange={(v) => setFilter('team', v)}
                blank="Any team" options={TEAMS.map((t) => [t, t.replace(/_/g, ' ')])} />
        <label className="text-[12px] text-ink2 flex items-center gap-1.5">
          <input type="checkbox" checked={params.get('overdue') === 'true'}
                 onChange={(e) => setFilter('overdue', e.target.checked ? 'true' : '')} />
          Overdue only
        </label>
        <button type="button" className="btn btn-ghost" onClick={() => setParams({})}>
          Reset
        </button>
      </div>

      {/* `category` and `assignee` are accepted by the query and can arrive from a
          saved view, but have no control above — say so rather than filtering the
          queue by something invisible. */}
      {(params.get('category') || params.get('assignee')) && (
        <div className="flex gap-2 flex-wrap items-center mb-3.5 text-[12px] text-ink2">
          {params.get('category') && (
            <span>
              Category <span className="font-mono text-ink">{params.get('category')}</span>{' '}
              <button type="button" className="text-accent"
                      onClick={() => setFilter('category', '')}>clear</button>
            </span>
          )}
          {params.get('assignee') && (
            <span>
              Assigned to <span className="font-mono text-ink">{params.get('assignee')}</span>{' '}
              <button type="button" className="text-accent"
                      onClick={() => setFilter('assignee', '')}>clear</button>
            </span>
          )}
        </div>
      )}

      {/* THE DOMAIN'S LIMIT TRAVELS WITH THE FILTER. A queue narrowed to
          "Interface Traffic Monitoring" is one screen a reader can reach without
          ever passing the tile that says we do not see traffic — and a filtered
          queue is the thing people send each other, so it arrives with no
          context at all. The qualifier is repeated here rather than assumed. */}
      {selectedDomain?.scope && (
        <p className="dom-scope mb-3.5 max-w-[80ch]">
          <strong className="text-ink2">{selectedDomain.label}:</strong>{' '}
          {selectedDomain.scope}
        </p>
      )}

      {user.can_write && <SaveViewForm />}

      {error && <div className="banner banner-bad" role="alert">{error}</div>}

      <div className={`${CARD} p-0 overflow-x-auto`}>
        <table className="w-full border-collapse">
          <thead>
            <tr>
              {user.can_write && (
                <th className={`${TH} w-[26px]`}>
                  <input
                    type="checkbox" checked={allSelected} aria-label="Select all"
                    onChange={(e) => setSelected(e.target.checked ? rows.map((r) => r.id) : [])}
                  />
                </th>
              )}
              <th className={`${TH} w-[42px]`}>P</th>
              <th className={`${TH} w-[88px]`}>Severity</th>
              <th className={`${TH} w-[118px]`}>Check</th>
              <th className={TH}>Title</th>
              <th className={`${TH} w-[100px]`}>System</th>
              <th className={`${TH} w-[118px]`}>Ownership</th>
              <th className={`${TH} w-[94px]`}>State</th>
              <th className={`${TH} w-[92px] text-right`}>Age / due</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((f) => (
              <tr key={f.id} className="hover:bg-panel2">
                {user.can_write && (
                  <td className={TD}>
                    <input
                      type="checkbox" checked={selected.includes(f.id)}
                      aria-label={`Select ${f.check_id}`}
                      onChange={(e) => setSelected((prev) =>
                        e.target.checked ? [...prev, f.id] : prev.filter((i) => i !== f.id))}
                    />
                  </td>
                )}
                {/* Tier first: it already folds in exploitability, exposure and
                    privilege, so it is a better sort key than raw severity. The
                    rationale is the prioritiser's own words — explainability is
                    the product, so it is carried as a tooltip rather than dropped. */}
                <td className={TD}>
                  {f.priority_tier
                    ? <span className={`tier tier-${f.priority_tier}`}
                            title={f.priority_rationale ?? undefined}>{f.priority_tier}</span>
                    : <span className="text-ink3 text-[12px]">—</span>}
                </td>
                <td className={TD}>
                  <span className={`pill sev-${f.severity ?? 'INFO'}`}>{f.severity ?? 'INFO'}</span>
                </td>
                <td className={`${TD} font-mono text-[12px]`}>
                  <Link className="text-accent" to={`/findings/${f.id}`}>{f.check_id}</Link>
                </td>
                <td className={TD}>
                  <Link className="text-accent" to={`/findings/${f.id}`}>{f.title}</Link>
                  {f.regression_count > 0 && (
                    <span className="pill st text-high ml-1.5"
                          title="previously resolved, then seen again">
                      regressed ×{f.regression_count}
                    </span>
                  )}
                  {f.expired_acceptance && (
                    <span className="pill st text-crit ml-1.5">acceptance expired</span>
                  )}
                  {f.assignee && (
                    <span className="text-[12px] text-ink2 ml-1.5">· {f.assignee}</span>
                  )}
                  {f.fingerprint_basis !== 'objects' && (
                    <span className="text-[12px] text-ink3 ml-1.5"
                          title={`matched across runs by ${f.fingerprint_basis}`}>
                      · {f.fingerprint_basis}
                    </span>
                  )}
                </td>
                <td className={`${TD} font-mono text-[12px]`}>
                  {f.sid ?? '—'}{f.system_client ? `/${f.system_client}` : ''}
                </td>
                <td className={TD}>
                  <span className={`own own-${f.remediation_owner}`}>
                    {OWNER_SHORT[f.remediation_owner]}
                  </span>
                </td>
                <td className={TD}>
                  <span className={`pill st st-${f.state}`}>{f.state.replace(/_/g, ' ')}</span>
                </td>
                <td className={`${TD} text-right font-mono text-[12px]`}>
                  {f.days_open}d
                  {f.is_overdue
                    ? <div className="text-[12px] text-crit">overdue</div>
                    : f.due_date && <div className="text-[12px] text-ink3">{dayMonth(f.due_date)}</div>}
                </td>
              </tr>
            ))}
            {page && rows.length === 0 && (
              <tr>
                <td colSpan={user.can_write ? 9 : 8} className="p-9 text-center text-ink2">
                  No findings match these filters.{' '}
                  {!params.get('state') && 'Resolved findings are hidden by default.'}
                </td>
              </tr>
            )}
            {!page && !error && (
              <tr>
                <td colSpan={user.can_write ? 9 : 8} className="p-9 text-center text-ink3">
                  Loading…
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Mounted for the whole session rather than only when rows exist: moving
          every finding on the page out of the default filter empties the queue,
          and an unmounted bulk bar would take the report of what it just did with
          it. The forms hide; the outcome stays. */}
      {user.can_write && (
        <BulkBar
          selected={selected}
          hasRows={rows.length > 0}
          onDone={() => setReloads((n) => n + 1)}
        />
      )}

      {page && page.pages > 1 && (
        <div className="mt-3.5 flex gap-2 items-center">
          {page.page > 1 && (
            <button type="button" className="btn btn-ghost"
                    onClick={() => goToPage(page.page - 1)}>Previous</button>
          )}
          <span className="text-ink2 text-[12px]">
            Page {page.page} of {page.pages}
          </span>
          {page.page < page.pages && (
            <button type="button" className="btn btn-ghost"
                    onClick={() => goToPage(page.page + 1)}>Next</button>
          )}
        </div>
      )}
    </>
  )
}

// ── bulk actions ─────────────────────────────────────────────────────────────

/**
 * The two things an analyst does to a selection.
 *
 * MOVING and ASSIGNING are separate because they are different events: a finding
 * can change hands three times while staying open, and folding that into the
 * state machine would fill the transition history with entries that say nothing
 * about the defect.
 *
 * The legality rules are the SERVER's — a reason for accept/false-positive, a
 * ticket for submitted-to-provider, and the transition table itself. They are not
 * re-implemented here: a client-side copy drifts, and the drift shows up as a
 * form that refuses a move the API would have allowed. The 400's message is shown
 * as written instead.
 */
function BulkBar({ selected, hasRows, onDone }: {
  selected: number[]; hasRows: boolean; onDone: () => void
}) {
  const [state, setState] = useState('submitted_to_provider')
  const [reason, setReason] = useState('')
  const [ticket, setTicket] = useState('')
  const [assignee, setAssignee] = useState('')
  const [team, setTeam] = useState('')
  const [due, setDue] = useState('')
  const [busy, setBusy] = useState(false)
  const [failure, setFailure] = useState('')
  const [moved, setMoved] = useState<BulkTransitionResult | null>(null)
  const [assigned, setAssigned] = useState<{ changed: number; failed: number[] } | null>(null)

  async function move(e: FormEvent) {
    e.preventDefault()
    setFailure(''); setMoved(null); setAssigned(null)
    if (!selected.length) { setFailure('Select at least one finding.'); return }
    setBusy(true)
    try {
      setMoved(await bulkSetState(selected, state, reason, ticket))
      onDone()
    } catch (err) {
      setFailure(describe(err))
    } finally {
      setBusy(false)
    }
  }

  // Assignment has no bulk endpoint, so this is one call per finding. It uses
  // allSettled rather than all: a finding that has since moved out of scope must
  // not abandon the rest of the batch half-applied and unreported.
  async function assign(e: FormEvent) {
    e.preventDefault()
    setFailure(''); setMoved(null); setAssigned(null)
    if (!selected.length) { setFailure('Select at least one finding.'); return }
    if (!assignee && !team && !due) { setFailure('Set an assignee, a team or a due date.'); return }
    setBusy(true)
    const results = await Promise.allSettled(selected.map((id) =>
      assignFinding(id, assignee || undefined, team || undefined, due || undefined)))
    setAssigned({
      changed: results.filter((r) => r.status === 'fulfilled' && r.value.changed).length,
      failed: selected.filter((_, i) => results[i].status === 'rejected'),
    })
    setBusy(false)
    onDone()
  }

  return (
    <>
      {hasRows && (
        <form onSubmit={move} className={`${CARD} mt-3 flex gap-2 flex-wrap items-end`}>
        <div>
          <label className={LABEL}>Move selected to</label>
          <select className="field mt-1" value={state} onChange={(e) => setState(e.target.value)}>
            {MOVES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </select>
        </div>
        <div className="flex-1 min-w-[200px]">
          <label className={LABEL}>Reason</label>
          <input className="field mt-1" value={reason} onChange={(e) => setReason(e.target.value)} />
        </div>
        <div>
          <label className={LABEL}>SAP ticket</label>
          <input className="field mt-1" value={ticket} onChange={(e) => setTicket(e.target.value)} />
        </div>
        <button type="submit" className="btn" disabled={busy}>
          Apply to selected{selected.length ? ` (${selected.length})` : ''}
        </button>
        <span className="basis-full text-[12px] text-ink3">
          Findings that cannot make the move are skipped and reported individually —
          the batch is deliberately not all-or-nothing.
        </span>
        </form>
      )}

      {hasRows && (
        <form onSubmit={assign} className={`${CARD} mt-3 flex gap-2 flex-wrap items-end`}>
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
        <button type="submit" className="btn btn-ghost" disabled={busy}>
          Assign selected{selected.length ? ` (${selected.length})` : ''}
        </button>
        <span className="basis-full text-[12px] text-ink3">
          Assigning is not a lifecycle event, so it leaves the state alone. A field
          left blank is left unchanged.
        </span>
        </form>
      )}

      {failure && <div className="banner banner-bad mt-3" role="alert">{failure}</div>}

      {moved && (
        <div className={`banner mt-3 ${moved.skipped_count ? 'banner-warn' : 'banner-ok'}`}>
          <strong className="font-semibold">
            {moved.applied_count} moved{moved.skipped_count ? `, ${moved.skipped_count} skipped` : ''}.
          </strong>
          {moved.skipped.length > 0 && (
            <ul className="mt-1.5 pl-4 list-disc">
              {moved.skipped.map((s) => (
                <li key={s.finding_id} className="text-[12px]">
                  <Link className="text-accent" to={`/findings/${s.finding_id}`}>
                    #{s.finding_id}
                  </Link>{' '}— {s.reason}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {assigned && (
        <div className={`banner mt-3 ${assigned.failed.length ? 'banner-warn' : 'banner-ok'}`}>
          <strong className="font-semibold">{assigned.changed} reassigned.</strong>
          {assigned.failed.length > 0 && (
            <> {assigned.failed.length} refused: {assigned.failed.join(', ')}.</>
          )}
        </div>
      )}
    </>
  )
}

// ── saving a view ────────────────────────────────────────────────────────────

/**
 * Save the current filters as a durable, permission-scoped URL.
 *
 * THE FILTERS ARE NOT IN THIS FORM. `POST /api/views` reads them off the Referer
 * header — the address bar is the body — which is why the screen keeps them in
 * useSearchParams. In `vite dev` the SPA is on :5173 and the API on :8000, so the
 * browser trims the Referer to the origin and a view saved from the dev server
 * comes out empty; that is a dev-server artefact, not a bug in this form.
 */
function SaveViewForm() {
  const [name, setName] = useState('')
  const [slug, setSlug] = useState('')
  const [description, setDescription] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [savedUrl, setSavedUrl] = useState('')

  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true); setError(''); setSavedUrl('')
    try {
      const result = await saveView(name, slug, { kind: 'findings', description })
      setSavedUrl(result.url)
    } catch (err) {
      setError(describe(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <details className="mb-3.5">
      <summary className="text-[12px] text-ink2 cursor-pointer">
        Save this view as a durable link
      </summary>
      <form onSubmit={submit} className={`${CARD} mt-2 flex gap-2 flex-wrap items-end`}>
        <div>
          <label className={LABEL}>Name</label>
          <input className="field mt-1" required placeholder="Basis worklist"
                 value={name} onChange={(e) => setName(e.target.value)} />
        </div>
        <div>
          <label className={LABEL}>URL slug</label>
          <input className="field mt-1" required placeholder="basis-worklist"
                 value={slug} onChange={(e) => setSlug(e.target.value)} />
        </div>
        <div className="flex-1 min-w-[180px]">
          <label className={LABEL}>Description</label>
          <input className="field mt-1" value={description}
                 onChange={(e) => setDescription(e.target.value)} />
        </div>
        <button type="submit" className="btn" disabled={busy}>Save view</button>
        <span className="basis-full text-[12px] text-ink3">
          Saves the filters above, never the rows — anyone opening the link sees only
          the systems they are entitled to.
        </span>
        {error && <div className="banner banner-bad basis-full mb-0" role="alert">{error}</div>}
        {savedUrl && (
          <div className="banner banner-ok basis-full mb-0">
            Saved as <span className="font-mono">{savedUrl}</span>. It joins the saved
            views in the sidebar the next time the console loads.
          </div>
        )}
      </form>
    </details>
  )
}

// ── plumbing ─────────────────────────────────────────────────────────────────

function Select({ value, onChange, blank, options }: {
  value: string
  onChange: (v: string) => void
  blank: string
  options: [string, string][]
}) {
  return (
    <select className="field w-auto" value={value} onChange={(e) => onChange(e.target.value)}>
      <option value="">{blank}</option>
      {options.map(([v, label]) => <option key={v} value={v}>{label}</option>)}
    </select>
  )
}

/** The query string IS the filter state. Everything the server's `list_findings`
 *  accepts is read back out of it, including the two with no control on screen:
 *  a saved view may carry `category` or `assignee`, and dropping them here would
 *  silently show a wider queue than the view describes. */
function queryFrom(sp: URLSearchParams): FindingFilters {
  const systemId = sp.get('system_id')
  const page = Number(sp.get('page') ?? '1')
  return {
    system_id: systemId ? Number(systemId) : null,
    state: (sp.get('state') as FindingState) || null,
    severity: (sp.get('severity') as Severity) || null,
    team: sp.get('team') || null,
    owner: (sp.get('owner') as RemediationOwner) || null,
    tier: (sp.get('tier') as PriorityTier) || null,
    category: sp.get('category') || null,
    assignee: sp.get('assignee') || null,
    domain: sp.get('domain') || null,
    overdue: sp.get('overdue') === 'true',
    page: Number.isFinite(page) && page > 0 ? Math.floor(page) : 1,
  }
}

/** '05 Feb' — the template's strftime('%d %b') for a due date.
 *  Read straight off the STRING rather than through `new Date`: 'YYYY-MM-DD'
 *  parses as UTC midnight, so it renders as the previous day for every reader
 *  west of Greenwich, and a due date that reads a day early is worse than no due
 *  date at all. */
function dayMonth(value: string): string {
  const m = /^\d{4}-(\d{2})-(\d{2})/.exec(value)
  if (!m) return value
  return `${m[2]} ${MONTHS[Number(m[1]) - 1] ?? m[1]}`
}

/** Branch on the STATUS, never on the message text. A 400 from a transition
 *  carries the server's own explanation of what the move was missing, so it is
 *  passed through as written. */
function describe(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.status === 403) return 'You are not permitted to make that change.'
    if (e.status >= 500) return `The server could not answer (${e.status}).`
    return e.message
  }
  return 'The console could not reach the server.'
}

const CARD = 'rounded-lg border border-line bg-panel p-4'
const TH = 'text-left px-2.5 py-2 text-[11px] font-semibold uppercase tracking-[.05em] text-ink3 border-b border-line'
const TD = 'px-2.5 py-[9px] align-top border-b border-line'
const LABEL = 'block text-[12px] text-ink3'

const TIERS: PriorityTier[] = ['P1', 'P2', 'P3', 'P4']
const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
const STATES: FindingState[] = [
  'open', 'submitted_to_provider', 'mitigated', 'accepted', 'false_positive', 'resolved',
]
const TEAMS = [
  'basis', 'authorizations', 'development', 'integration', 'data_protection', 'identity',
]
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

/** The four ownership classes, in the filter's wording. Reporting an SAP-owned
 *  setting as a customer failure — or as "unknown" — is how a RISE report fills
 *  with unactionable noise. */
const OWNER_FILTER: [string, string][] = [
  ['customer_fixable', 'Yours to fix'],
  ['ticket_to_sap', 'Raise with SAP'],
  ['provider_owned', "SAP's under RISE"],
  ['not_assessable', 'Out of reach'],
]

/** The column is 118px wide, so the badge uses the short forms the table does. */
const OWNER_SHORT: Record<RemediationOwner, string> = {
  customer_fixable: 'Yours to fix',
  ticket_to_sap: 'Raise with SAP',
  provider_owned: "SAP's",
  not_assessable: 'Out of reach',
}

/** The moves a person may make. `resolved` is absent on purpose: it is set by the
 *  SCANNER not observing the finding again, never by a human clicking a button. */
const MOVES: [string, string][] = [
  ['submitted_to_provider', 'Submitted to SAP'],
  ['mitigated', 'Mitigated'],
  ['accepted', 'Risk accepted'],
  ['false_positive', 'False positive'],
  ['open', 'Re-open'],
]
