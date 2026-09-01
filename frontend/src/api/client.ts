// The typed client. One function per /api endpoint, and the ONLY place in the
// console that calls fetch for data.
//
// THERE IS ONE MODE AND IT TALKS TO THE API.
// The sibling product's client defaulted to a "sample" mode that read bundled
// fixtures. Nothing ever set the variable that switched it off, so the shipped
// image had its entire authentication feature tree-shaken out of the bundle — it
// passed every test and was absent from the artefact. MonitorRisk has no sample
// mode and must not gain one: this is an OFFLINE scanner whose whole value is
// that the numbers came from the customer's own exports, and a console that can
// render plausible findings from a fixture is a liability, not a demo.
//
// AUTHENTICATION IS A COOKIE AND IS NOT HANDLED HERE.
// The session cookie is HttpOnly, so JavaScript cannot read it — which is the
// point: an XSS bug in the console cannot exfiltrate a session. `fetch` defaults
// to credentials: 'same-origin', so it rides along untouched. There is no token,
// no header, and nothing to store.
//
// WRITES ARE FORM-ENCODED, READS ARE JSON. Not an inconsistency: the write
// endpoints under /api take `Form(...)` parameters because the Jinja pages used
// to post to them directly. Those pages are now retired, and the shape stays
// anyway — it is a published API that integrators call, and churning every write
// body to JSON would break them to buy this file nothing. `form()` below exists
// so a screen never hand-rolls a URLSearchParams and gets it subtly wrong.
//
// /api/auth/* and /api/account/* are the exception and take JSON bodies. That is
// a CSRF control rather than a style choice — see the header of
// server/api_auth.py — and it must not be "harmonised" with the above.

import type {
  AccountInfo, AssignResult, BulkTransitionResult, ChangesSince, CheckDoc,
  CheckIndexEntry, ChokepointsView,
  SeveringSet, Coverage, CrqControlsView,
  CrqParametersView, CrqQuantifyResult, CrqTrendPoint, CsfFunctionView,
  CsfView, Dashboard, DomainsView, FindingDetail, FindingFilters,
  FindingHistory, FindingPage, GeneratedPassword, Health, Journey, Landscape,
  Me, PathView, PathsOverview, RequirementDoc, ResolvedView, RiskView,
  RunDiff, SapSystem, SaveViewResult, SavedView, ScanRun, SecurityDomain,
  TotpConfirmed, TotpEnrolment, TotpStatus, TransitionResult, UploadResult
} from './types'

/** Same-origin by default: FastAPI serves this bundle and the API. The override
 *  exists for `vite dev`, where the SPA is on :5173 and the API on :8000 — the
 *  dev proxy handles that without changing this value, so in practice it is only
 *  ever needed for an unusual deployment. */
const API_BASE = (import.meta.env.VITE_API_BASE as string | undefined) ?? '/api'

/** A failed API call, carrying the status so a caller can distinguish "you may
 *  not" (403) from "it is not there" (404) from "the server broke" (5xx).
 *  Matching on message text is how that distinction gets lost. */
export class ApiError extends Error {
  readonly status: number
  /** Set when the server refused a sign-in because it wants a second factor.
   *
   *  It rides on the ERROR rather than on a success payload because the server
   *  answers 401 — there is no session yet, and inventing a 200 "half signed in"
   *  state would be a lie every other screen would have to defend against. It is
   *  a TOP-LEVEL field in the body, not inside `detail`, because `failure()`
   *  below deliberately only unwraps a string `detail`. */
  readonly totpRequired: boolean
  constructor(status: number, message: string, totpRequired = false) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.totpRequired = totpRequired
  }
}

/** The server reports failures as `{"detail": ...}` — FastAPI's own shape, and
 *  the one every hand-written JSONResponse in server/ follows. `detail` is
 *  usually a string; for the forced-password-change gate it is a string plus a
 *  `change_at`, and for a 422 it is a list of validation objects. */
async function failure(r: Response): Promise<ApiError> {
  try {
    const body = await r.json()
    const d = body?.detail
    const totp = body?.totp_required === true
    if (typeof d === 'string') return new ApiError(r.status, d, totp)
    if (Array.isArray(d) && d.length) return new ApiError(r.status, 'Invalid request')
    if (totp) return new ApiError(r.status, `${r.status} ${r.statusText}`, true)
  } catch {
    /* a non-JSON error body is still a failure */
  }
  return new ApiError(r.status, `${r.status} ${r.statusText}`)
}

async function get<T>(path: string, params?: Record<string, unknown>): Promise<T> {
  const r = await fetch(API_BASE + path + qs(params), {
    headers: { Accept: 'application/json' },
  })
  if (!r.ok) throw await failure(r)
  return (await r.json()) as T
}

/** POST a form body — see the header note on why writes are form-encoded.
 *  `undefined` and `null` values are dropped rather than sent as the strings
 *  "undefined"/"null", which is what URLSearchParams would otherwise do and
 *  which the server would then store verbatim. */
async function post<T>(path: string, fields?: Record<string, unknown>,
                       init?: RequestInit): Promise<T> {
  const r = await fetch(API_BASE + path, {
    method: 'POST',
    body: fields ? form(fields) : undefined,
    ...init,
  })
  if (!r.ok) throw await failure(r)
  const text = await r.text()
  return (text ? JSON.parse(text) : {}) as T
}

function form(fields: Record<string, unknown>): URLSearchParams {
  const body = new URLSearchParams()
  for (const [k, v] of Object.entries(fields)) {
    if (v === undefined || v === null || v === '') continue
    body.set(k, String(v))
  }
  return body
}

function qs(params?: Record<string, unknown>): string {
  if (!params) return ''
  const sp = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === '') continue
    if (typeof v === 'boolean' && !v) continue   // `overdue=false` is the default
    sp.set(k, String(v))
  }
  const s = sp.toString()
  return s ? `?${s}` : ''
}

// ══ authentication and account ══════════════════════════════════════════════

/** The signed-in user, or null when there is no session.
 *
 *  Never throws on a 401: "not signed in" is an expected state on first load,
 *  not an error. Every OTHER status still throws — a 500 from the session store
 *  is not an anonymous visitor, and treating it as one would send someone to a
 *  sign-in form that is about to fail the same way. */
export async function me(): Promise<Me | null> {
  const r = await fetch(`${API_BASE}/auth/me`, { headers: { Accept: 'application/json' } })
  if (r.status === 401) return null
  if (!r.ok) throw await failure(r)
  return (await r.json()) as Me
}

/** Sign in. The rejection message is identical for an unknown username and a
 *  wrong password — do not "improve" it in the UI either, the distinction is a
 *  username oracle. */
export async function login(
  username: string, password: string, totpCode?: string,
): Promise<Me> {
  const r = await fetch(`${API_BASE}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    // `totp_code` carries either six digits or a recovery code — deliberately one
    // field, so somebody whose phone is gone does not have to find a different box.
    body: JSON.stringify({ username, password, totp_code: totpCode || undefined }),
  })
  if (!r.ok) throw await failure(r)
  return (await r.json()) as Me
}


// ── Second factor ───────────────────────────────────────────────────────────
// Every mutation re-sends the current password. That is the SERVER's rule, not a
// UI choice — a stolen session must not be enough to bind or remove a factor —
// so a screen cannot opt out of it by forgetting to ask. All four take JSON
// bodies, which is the CSRF control described in server/api_auth.py's header.

async function accountJson<T>(path: string, body: unknown): Promise<T> {
  const r = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify(body),
  })
  if (!r.ok) throw await failure(r)
  return (await r.json()) as T
}

export async function totpStatus(): Promise<TotpStatus> {
  const r = await fetch(`${API_BASE}/account/totp`, {
    headers: { Accept: 'application/json' },
  })
  if (!r.ok) throw await failure(r)
  return (await r.json()) as TotpStatus
}

export function totpBegin(current: string): Promise<TotpEnrolment> {
  return accountJson('/account/totp/begin', { current })
}

export function totpConfirm(current: string, code: string): Promise<TotpConfirmed> {
  return accountJson('/account/totp/confirm', { current, code })
}

export function totpDisable(current: string, code: string): Promise<{ enabled: boolean }> {
  return accountJson('/account/totp/disable', { current, code })
}

export function totpRegenerateRecovery(
  current: string, code: string,
): Promise<{ recovery_codes: string[] }> {
  return accountJson('/account/totp/recovery', { current, code })
}

/** End the session server-side; clearing the cookie is the consequence.
 *
 *  THROWS on a non-2xx rather than being fire-and-forget. A 500 from the session
 *  store would otherwise be indistinguishable from a clean sign-out, leaving the
 *  session alive for its full window while the user looks at a login form.
 *
 *  It always settles: `fetch` has no default timeout, and a backend that accepts
 *  the connection then stalls would neither resolve nor reject, stranding a
 *  caller on "Signing out…" forever. `keepalive` so the request survives the
 *  navigation that follows — a cancelled sign-out is the worst outcome available,
 *  because it looks exactly like success. */
export async function logout(): Promise<void> {
  const r = await fetch(`${API_BASE}/auth/logout`, {
    method: 'POST', keepalive: true, signal: AbortSignal.timeout(5000),
  })
  if (!r.ok) throw await failure(r)
}

/** Everything the account screen renders. `users` is empty for a non-admin. */
export function account(): Promise<AccountInfo> {
  return get<AccountInfo>('/account')
}

/** Change your own password. The current one is required even though you are
 *  signed in: a stolen session must not be enough to take the account over.
 *  Every OTHER session for the account is dropped as a result. */
export async function changePassword(
  current: string, new1: string, new2: string,
): Promise<{ changed: boolean; other_sessions_revoked: boolean }> {
  const r = await fetch(`${API_BASE}/account/password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ current, new1, new2 }),
  })
  if (!r.ok) throw await failure(r)
  return await r.json()
}

/** Admin: reset another user's password to a GENERATED one.
 *
 *  The returned password is shown ONCE and exists nowhere else — not in the
 *  audit log, not in a URL. Do not put it in a route parameter, localStorage or
 *  anything that survives the render. */
export function resetUserPassword(userId: number): Promise<GeneratedPassword> {
  return post<GeneratedPassword>(`/account/reset/${userId}`)
}

// ══ dashboard ═══════════════════════════════════════════════════════════════

export function dashboard(): Promise<Dashboard> {
  return get<Dashboard>('/dashboard')
}

/** Systems in the caller's scope. Also the filter vocabulary for the queue. */
export async function systems(): Promise<SapSystem[]> {
  return (await get<{ systems: SapSystem[] }>('/systems')).systems
}

/** Landscapes — the upload form's required `landscape_id`. Not scoped: scoping
 *  is per system, and a landscape carries no findings of its own. */
export async function landscapes(): Promise<Landscape[]> {
  return (await get<{ landscapes: Landscape[] }>('/landscapes')).landscapes
}

// ══ findings ════════════════════════════════════════════════════════════════

/** The triage queue, ordered priority tier first and severity second — the tier
 *  already folds in exploitability, exposure and privilege, so do not re-sort by
 *  raw severity in the client. */
export function findings(filters: FindingFilters = {}): Promise<FindingPage> {
  return get<FindingPage>('/findings', filters as Record<string, unknown>)
}

export function finding(id: number): Promise<FindingDetail> {
  return get<FindingDetail>(`/findings/${id}`)
}

/** The lifecycle trail and the per-run observations for one finding. */
export function findingHistory(id: number): Promise<FindingHistory> {
  return get<FindingHistory>(`/findings/${id}/history`)
}

/** Everything that moved since a run — the incremental sync an incumbent's
 *  integrators explicitly cannot get. */
export function findingChanges(sinceRun: number): Promise<ChangesSince> {
  return get<ChangesSince>('/findings/changes', { since_run: sinceRun })
}

/** Move one finding. The server refuses illegal moves and requires a reason for
 *  `false_positive`/`accepted` and a ticket for `submitted_to_provider` — surface
 *  the 400's message, do not pre-empt it with a client-side rule that will drift. */
export function setFindingState(
  id: number, state: string, reason = '', ticket = '',
): Promise<TransitionResult> {
  return post<TransitionResult>(`/findings/${id}/state`, { state, reason, ticket })
}

/** Assign work without changing state: a finding can change hands three times
 *  while staying open, and that is not a lifecycle event. */
export function assignFinding(
  id: number, assignee?: string, team?: string, dueDate?: string,
): Promise<AssignResult> {
  return post<AssignResult>(`/findings/${id}/assign`,
                            { assignee, team, due_date: dueDate })
}

/** Move several findings. Deliberately NOT all-or-nothing — the moves that were
 *  legal are applied and the rest come back in `skipped` with a reason each.
 *  Render both halves; reporting only the successes misdescribes what happened. */
export function bulkSetState(
  ids: number[], state: string, reason = '', ticket = '',
): Promise<BulkTransitionResult> {
  return post<BulkTransitionResult>('/findings/bulk-state',
                                    { finding_ids: ids.join(','), state, reason, ticket })
}

// ══ attack paths ════════════════════════════════════════════════════════════
// Called RISK PATHS in every word a reader sees. The wire shape, the table and
// the type keep `attack_path`: renaming those is a schema migration that moves
// every stored path's identity, and this was a change of articulation.

export function paths(includeClosed = false): Promise<PathsOverview> {
  return get<PathsOverview>('/paths', { include_closed: includeClosed })
}

export function path(id: number): Promise<PathView> {
  return get<PathView>(`/paths/${id}`)
}

/** The choke-point worklist. Its own call rather than a slice of `paths()`,
 *  because that one caps the list at 15 to keep the paths screen legible and a
 *  cap that exists for another screen must not decide how much work is shown
 *  here. */
export function severingSets(): Promise<{ scenarios: SeveringSet[] }> {
  return get<{ scenarios: SeveringSet[] }>('/severing-sets')
}

export function chokepoints(limit?: number): Promise<ChokepointsView> {
  return get<ChokepointsView>('/chokepoints', limit ? { limit } : undefined)
}

// ══ the check catalogue and SAP's Baseline requirements ═════════════════════
// Product facts, not tenant data: these carry no row scoping and need none. The
// estate-specific half is a link to the findings queue, which is scoped once, in
// the place every other filter is scoped.

export function checkDoc(id: string): Promise<CheckDoc> {
  return get<CheckDoc>(`/checks/${encodeURIComponent(id)}`)
}

export function requirementDoc(id: string): Promise<RequirementDoc> {
  return get<RequirementDoc>(`/requirements/${encodeURIComponent(id)}`)
}

export function checkIndex(): Promise<{ checks: CheckIndexEntry[] }> {
  return get<{ checks: CheckIndexEntry[] }>('/checks')
}

// ══ financial risk, journey, coverage ═══════════════════════════════════════

export function risk(): Promise<RiskView> {
  return get<RiskView>('/risk')
}

export function trend(days = 180): Promise<Journey> {
  return get<Journey>('/trend', { days })
}

export function coverage(): Promise<Coverage> {
  return get<Coverage>('/coverage')
}

// ══ runs and upload ═════════════════════════════════════════════════════════

export function run(id: number): Promise<ScanRun> {
  return get<ScanRun>(`/runs/${id}`)
}

/** New / persisting / resolved / regressed for one run. Separate from `run()` on
 *  purpose: `run()` is cheap enough to poll while a scan is in flight. */
export function runDiff(id: number): Promise<RunDiff> {
  return get<RunDiff>(`/runs/${id}/diff`)
}

/** Request cancellation. The worker checks between modules and stops cleanly —
 *  the response only means the request was recorded, so keep polling `run()`. */
export function cancelRun(id: number): Promise<{ run_id: number; cancel_requested: boolean }> {
  return post(`/runs/${id}/cancel`)
}

/** Upload an export bundle and start a scan.
 *
 *  multipart, so this one does NOT go through `post()`. Do not set Content-Type:
 *  the browser must add the multipart boundary itself, and a hand-set header
 *  produces a body FastAPI cannot parse.
 *
 *  Returns as soon as the files are stored — the scan runs in a thread pool.
 *  Poll `run(result.run_id)` for progress. */
export async function upload(
  files: File[], landscapeId: number,
  opts: { systemId?: number; sid?: string; client?: string } = {},
): Promise<UploadResult> {
  const body = new FormData()
  for (const f of files) body.append('files', f)
  body.append('landscape_id', String(landscapeId))
  if (opts.systemId !== undefined) body.append('system_id', String(opts.systemId))
  if (opts.sid) body.append('sid', opts.sid)
  if (opts.client) body.append('client', opts.client)

  const r = await fetch(`${API_BASE}/upload`, { method: 'POST', body })
  if (!r.ok) throw await failure(r)
  return (await r.json()) as UploadResult
}

// ══ saved views ═════════════════════════════════════════════════════════════

/** Views visible to this caller: their own, plus the shared ones. */
export async function views(kind?: string): Promise<SavedView[]> {
  return (await get<{ views: SavedView[] }>('/views', { kind })).views
}

/** Resolve a saved view to the filters a screen should apply.
 *
 *  It returns FILTERS, never rows. That is what makes a shared link safe: the
 *  receiving screen re-runs the query under its own caller's scope, so two people
 *  following the same URL each see only the systems they are entitled to. */
export function view(slug: string): Promise<ResolvedView> {
  return get<ResolvedView>(`/views/${encodeURIComponent(slug)}`)
}

/** Save the current filters as a durable URL.
 *
 *  THE SERVER READS THE FILTERS OFF THE REFERER, not off this body — "save this
 *  view" means "save what I am looking at". So the caller must have the filters
 *  in its own address bar before calling: a screen that keeps filter state only
 *  in React will save an empty view and the failure is silent. Put the filters
 *  in the query string (useSearchParams) and this works. */
export function saveView(
  name: string, slug: string,
  opts: { kind?: string; shared?: boolean; description?: string } = {},
): Promise<SaveViewResult> {
  return post<SaveViewResult>('/views', {
    name, slug,
    kind: opts.kind ?? 'findings',
    shared: opts.shared ?? true,
    description: opts.description ?? '',
  })
}

// ══ operational ═════════════════════════════════════════════════════════════

/** /health is NOT under /api and is unauthenticated — it is the container's
 *  liveness probe. Degraded components are reported, never hidden. */
export async function health(): Promise<Health> {
  const r = await fetch('/health', { headers: { Accept: 'application/json' } })
  if (!r.ok) throw await failure(r)
  return (await r.json()) as Health
}

// ══ NIST CSF 2.0 ════════════════════════════════════════════════════════════
export function csf(): Promise<CsfView> {
  return get<CsfView>('/csf')
}
export function csfFunction(functionId: string): Promise<CsfFunctionView> {
  return get<CsfFunctionView>(`/csf/${encodeURIComponent(functionId)}`)
}

// ══ Cyber Risk Quantification ═══════════════════════════════════════════════
export function crqParameters(landscapeId: number): Promise<CrqParametersView> {
  return get<CrqParametersView>(`/crq/parameters?landscape_id=${landscapeId}`)
}
export function saveCrqParameters(
  landscapeId: number, answers: Record<string, number>, note: string,
): Promise<{ id: number }> {
  return post<{ id: number }>('/crq/parameters', {
    landscape_id: String(landscapeId),
    answers_json: JSON.stringify(answers),
    note,
  })
}
export function crqQuantify(
  landscapeId: number, answers: Record<string, number> | null, simulations = 20000,
): Promise<CrqQuantifyResult> {
  return post<CrqQuantifyResult>('/crq/quantify', {
    landscape_id: String(landscapeId),
    ...(answers ? { answers_json: JSON.stringify(answers) } : {}),
    simulations: String(simulations),
  })
}
export function crqControls(landscapeId: number): Promise<CrqControlsView> {
  return get<CrqControlsView>(`/crq/controls?landscape_id=${landscapeId}`)
}
export function crqTrend(limit = 12): Promise<{ points: CrqTrendPoint[] }> {
  return get<{ points: CrqTrendPoint[] }>(`/crq/trend?limit=${limit}`)
}

// ══ The twelve security domains ═════════════════════════════════════════════
export function domains(): Promise<DomainsView> {
  return get<DomainsView>('/domains')
}
export function domain(id: string): Promise<SecurityDomain> {
  return get<SecurityDomain>(`/domains/${encodeURIComponent(id)}`)
}
