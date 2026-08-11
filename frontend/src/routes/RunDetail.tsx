/*
 * Copyright (c) 2026 Krishnendu De. All Rights Reserved.
 *
 * Author : Krishnendu De
 * Coding Assistance : Claude Code
 * Code Security Assistance : Code QL
 */

import { useEffect, useRef, useState } from 'react'
import { Link, useParams } from 'react-router'
import { ApiError, cancelRun, run as fetchRun, runDiff as fetchDiff } from '../api/client'
import type { RunDiff, RunStatus, ScanRun } from '../api/types'
import { useSession } from '../lib/session'
import { useTitle } from '../lib/title'

/**
 * One scan run: what it found, what it could not see, and — while it is still
 * going — where it has got to.
 *
 * Ported from server/templates/run_detail.html, which rendered a FINISHED run and
 * nothing else. It had no progress, no cancel and no notion of a run in flight,
 * because a Jinja page is a photograph: whatever the row said at request time is
 * what it showed, for ever. Everything below the coverage banner is that page,
 * behaviour for behaviour; everything above it is what a page that can re-read the
 * row is obliged to do with the ability.
 *
 * A SCAN THAT DIED MUST NOT RENDER AS STILL RUNNING. This screen never says a run
 * is progressing — it says what the scanner last wrote and when. The distinction
 * is not pedantry: `scan_run.status` is updated by a worker in a thread pool, so a
 * container restart leaves a row on 'scanning' with nothing left alive to move it
 * off, and a spinner over that row is the console asserting something it has no
 * way to know. Three states are therefore reported separately and never merged:
 * the run's own status, whether the last poll SUCCEEDED, and how long the row has
 * been saying the same thing.
 *
 * THE DIFF IS NOT FETCHED UNTIL THE RUN IS TERMINAL. `run()` is one row and is
 * cheap enough to poll; `runDiff()` is four aggregates and is deliberately a
 * separate endpoint for exactly that reason. Fetching it mid-run would also be
 * dishonest in a quieter way: findings are written inside the pipeline's single
 * transaction, so a diff taken while a scan is running renders "New 0" over a
 * result set that is merely unfinished — and "0" reads as "clean".
 */

/** In-flight statuses. Everything else is terminal, and the difference decides
 *  whether this screen polls at all. Mirrors the status list in the UPDATE that
 *  server/app.py:cancel_run guards with. */
const IN_FLIGHT: ReadonlySet<RunStatus> =
  new Set<RunStatus>(['pending', 'parsing', 'scanning', 'deriving'])

/** How often an in-flight run is re-read. A run is ~23 modules and a module takes
 *  seconds, so three seconds is finer than the thing being watched changes and
 *  costs one indexed row read. */
const POLL_MS = 3_000

/** How long the row may say exactly the same thing before the screen mentions it.
 *  NOT a claim that the scan died — nothing in the browser can know that. It is
 *  the difference between "still running" (which the row cannot promise) and
 *  "this is the last thing the scanner wrote, at this time" (which is all the row
 *  has ever said). */
const STALL_MS = 120_000

/** What each in-flight status actually means, in the operator's language rather
 *  than the enum's. server/ingest.py:scan_directory sets them in this order. */
const PHASE: Record<RunStatus, string> = {
  pending: 'Queued. The scan starts when a worker picks the bundle up.',
  parsing: 'Reading the uploaded export files.',
  scanning: 'Running the audit modules.',
  deriving: 'Deriving attack paths, financial risk and the run-over-run diff.',
  complete: 'Finished.',
  failed: 'Stopped on an error.',
  cancelled: 'Stopped on request.',
}

/** Colour for the status chip.
 *
 *  INLINE, AND DELIBERATELY NOT A TAILWIND UTILITY. `.st` in src/index.css is
 *  unlayered CSS, and unlayered rules beat everything Tailwind emits (its
 *  utilities live in `@layer utilities`), so `text-crit` on a `.st` chip loses
 *  silently. The run statuses have no `.st-*` rules of their own — base.html never
 *  wrote any, which is why the Jinja page renders a failed run in the same neutral
 *  grey as a finished one — and index.css belongs to the shell, not to this
 *  screen. An inline colour is the honest local fix. */
const STATUS_COLOR: Record<RunStatus, string> = {
  pending: 'var(--accent)', parsing: 'var(--accent)',
  scanning: 'var(--accent)', deriving: 'var(--accent)',
  complete: 'var(--ok)', failed: 'var(--crit)', cancelled: 'var(--ink-faint)',
}

/** Same reasoning as STATUS_COLOR, for the per-module chips. */
const MODULE_COLOR: Record<string, string> = {
  complete: 'var(--ok)', ok: 'var(--ok)',
  degraded: 'var(--high)', failed: 'var(--crit)',
  skipped: 'var(--ink-faint)', not_run: 'var(--ink-faint)',
}

/** The shape server/coverage.py:build_manifest writes into `scan_run.coverage`.
 *
 *  It is a jsonb column, so api/types.ts types it `Record<string, unknown>` and
 *  refuses to guess — this is the transcription, kept beside the only screen that
 *  reads it. EVERY FIELD IS OPTIONAL: the column defaults to `{}` and a run that
 *  failed before the manifest was built keeps that default, so a screen that
 *  assumes the keys exist crashes on precisely the runs worth looking at. */
interface CoverageModule {
  status?: string
  sources_missing?: string[]
  rise_scope?: string
}
interface CoverageManifest {
  deployment_mode?: string
  summary?: string
  counts?: Record<string, number>
  modules?: Record<string, CoverageModule>
}

/** One entry of `scan_run.module_status`, written by server/ingest.py:run_auditors.
 *  A failed auditor keeps its traceback here because a component that fails and
 *  yields no detail anywhere is a documented complaint about the incumbent. */
interface ModuleRun {
  status?: string
  findings?: number
  error?: string
  traceback?: string
}

/** A poll result and the two timestamps that make it interpretable: when it was
 *  read, and when the row last actually CHANGED. Kept together in one state value
 *  so a render can never pair a fresh run with a stale clock. */
interface Poll {
  run: ScanRun
  at: number
  changedAt: number
}

/** `YYYY-MM-DD HH:MM` in the reader's own zone — the format run_detail.html
 *  produced with strftime, kept so the two consoles read alike while both run.
 *  `started_at` is timestamptz, so the ISO string carries an offset and Date
 *  parses it unambiguously; a bad value is returned verbatim rather than shown as
 *  "Invalid Date". */
function stamp(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ` +
         `${p(d.getHours())}:${p(d.getMinutes())}`
}

function clock(ms: number): string {
  return new Date(ms).toLocaleTimeString()
}

/** One message per status, because a caller branching on message text is how the
 *  distinction between "not there", "not yours" and "broken" gets lost. */
function describe(err: unknown, runId: number): string {
  if (!(err instanceof ApiError)) return 'Could not reach the server.'
  if (err.status === 404) {
    return `Run #${runId} does not exist, or it is outside the systems you are ` +
           'scoped to. The server answers identically for both so that run ids ' +
           'cannot be probed for existence.'
  }
  if (err.status === 401) return 'Your session has ended. Sign in again.'
  return err.message
}

function Kpi({ label, value, tone, note }: {
  label: string; value: number; tone?: string; note?: string
}) {
  return (
    <div className="rounded-lg border border-line bg-panel p-4">
      <h3 className="m-0 mb-3 text-[12px] font-semibold uppercase tracking-[.06em] text-ink3">
        {label}
      </h3>
      <div className={`text-[30px] font-semibold leading-none tracking-tight ${tone ?? ''}`}>
        {value}
      </div>
      {note && <div className="mt-1.5 text-[12px] text-ink2">{note}</div>}
    </div>
  )
}

/** Severity chip. `severity` is nullable on a finding row, and the Jinja template
 *  rendered a null one as the literal string "None"; an em-dash in the INFO chip
 *  says the same thing without asserting a severity nobody recorded. */
function Sev({ value }: { value: string | null }) {
  return <span className={`pill sev-${value ?? 'INFO'}`}>{value ?? '—'}</span>
}

const TH = 'text-left text-[11px] font-semibold uppercase tracking-[.05em] ' +
           'text-ink3 px-2.5 py-2 border-b border-line'
const TD = 'px-2.5 py-2.5 border-b border-line align-top'

export function RunDetail() {
  const { id } = useParams<{ id: string }>()
  const runId = Number(id)
  const valid = /^\d+$/.test(id ?? '') && runId > 0
  const { user } = useSession()

  // run_detail.html's `Run #{{ run.id }}`. From the URL rather than from the
  // fetched row: the id is known before the first poll returns, and a run left
  // open in a background tab while another is watched is exactly the case the
  // title has to disambiguate.
  useTitle(valid ? `Run #${runId}` : 'Scan run')

  const [poll, setPoll] = useState<Poll | null>(null)
  // `retryable` is false only for the two answers that will not change on their
  // own: a 404 (no such run, or not yours) and a 401 (the session ended). A 500
  // or a dropped connection gets a button, because the run behind it is probably
  // fine and the container it lives in is probably coming back.
  const [loadError, setLoadError] =
    useState<{ message: string; retryable: boolean } | null>(null)
  const [attempt, setAttempt] = useState(0)
  const [pollError, setPollError] = useState<string | null>(null)
  const [diff, setDiff] = useState<RunDiff | null>(null)
  const [diffError, setDiffError] = useState<string | null>(null)
  const [cancelSent, setCancelSent] = useState(false)
  const [cancelBusy, setCancelBusy] = useState(false)
  const [cancelError, setCancelError] = useState<string | null>(null)

  // Whether a first read ever succeeded. It decides how a failure is reported: a
  // failure with nothing on screen replaces the screen, one with a run already
  // rendered is an interruption and must not throw away the last known state —
  // that state is the most useful thing the screen has when the server is down.
  const everLoaded = useRef(false)

  useEffect(() => {
    if (!valid) return
    everLoaded.current = false
    setPoll(null); setDiff(null); setDiffError(null)
    setLoadError(null); setPollError(null)
    setCancelSent(false); setCancelError(null)

    let stopped = false
    let timer: ReturnType<typeof setTimeout> | undefined

    // A timeout CHAIN rather than setInterval: an interval fires regardless of
    // whether the previous request came back, so a server taking longer than the
    // period accumulates overlapping requests and the responses can land out of
    // order — which on this screen would mean progress appearing to go backwards.
    async function tick() {
      try {
        const r = await fetchRun(runId)
        if (stopped) return
        everLoaded.current = true
        setPollError(null)
        setPoll((prev) => {
          const now = Date.now()
          const same = prev !== null
            && prev.run.status === r.status
            && prev.run.progress_done === r.progress_done
            && prev.run.cancel_requested === r.cancel_requested
          return { run: r, at: now, changedAt: same ? prev.changedAt : now }
        })
        if (IN_FLIGHT.has(r.status)) timer = setTimeout(tick, POLL_MS)
      } catch (err) {
        if (stopped) return
        const message = describe(err, runId)
        if (!everLoaded.current) {
          const dead = err instanceof ApiError && (err.status === 404 || err.status === 401)
          setLoadError({ message, retryable: !dead })
          return                       // nothing on screen to keep fresh
        }
        // Keep the run on screen and keep trying, at half the rate. A transient
        // 502 from a restarting container must not blank a page someone is
        // watching, but it must also not pass unremarked as a live scan.
        setPollError(message)
        timer = setTimeout(tick, POLL_MS * 2)
      }
    }

    void tick()
    return () => { stopped = true; if (timer) clearTimeout(timer) }
  }, [runId, valid, attempt])

  // The diff, once — and only once the run is terminal. Keyed on the status so the
  // transition from 'deriving' to 'complete' is what triggers it.
  const status = poll?.run.status
  useEffect(() => {
    if (status === undefined || IN_FLIGHT.has(status)) return
    let stopped = false
    fetchDiff(runId)
      .then((d) => { if (!stopped) { setDiff(d); setDiffError(null) } })
      .catch((err) => { if (!stopped) setDiffError(describe(err, runId)) })
    return () => { stopped = true }
  }, [runId, status])

  async function requestCancel() {
    setCancelBusy(true)
    setCancelError(null)
    try {
      await cancelRun(runId)
      // The response only means the request was RECORDED — server/app.py returns
      // `cancel_requested: true` whether or not the UPDATE matched a row, and the
      // worker checks the flag between modules. So this flips the copy, and the
      // poll is what confirms it.
      setCancelSent(true)
    } catch (err) {
      setCancelError(err instanceof ApiError && err.status === 403
        ? 'Cancelling a run requires the analyst role.'
        : describe(err, runId))
    } finally {
      setCancelBusy(false)
    }
  }

  if (!valid) {
    return (
      <div className="max-w-2xl">
        <h1 className="mb-1 text-[21px] font-semibold tracking-tight text-ink">Scan run</h1>
        <div className="banner banner-bad">
          <strong>{id}</strong> is not a run id.
        </div>
      </div>
    )
  }

  if (loadError) {
    return (
      <div className="max-w-2xl">
        <h1 className="mb-1 text-[21px] font-semibold tracking-tight text-ink">
          Scan run #{runId}
        </h1>
        <div className="banner banner-bad" role="alert">{loadError.message}</div>
        {loadError.retryable && (
          <button type="button" className="btn btn-ghost"
                  onClick={() => setAttempt((n) => n + 1)}>
            Try again
          </button>
        )}
      </div>
    )
  }

  if (!poll) {
    return <p className="text-ink2">Reading run #{runId}…</p>
  }

  const r = poll.run
  const inFlight = IN_FLIGHT.has(r.status)
  const stalled = inFlight && Date.now() - poll.changedAt > STALL_MS
  const cancelling = r.cancel_requested || cancelSent

  const cov = (r.coverage ?? {}) as CoverageManifest
  const covModules = Object.entries(cov.modules ?? {})
    .sort(([a], [b]) => a.localeCompare(b))
  const rise = (cov.deployment_mode ?? '').startsWith('rise')
  const covDegraded = (cov.counts?.modules_degraded ?? 0) > 0
                   || (cov.counts?.modules_skipped ?? 0) > 0

  const moduleErrors = Object.entries((r.module_status ?? {}) as Record<string, ModuleRun>)
    .filter(([, m]) => m.status === 'failed')

  const pct = r.progress_total > 0
    ? Math.min(100, Math.round((r.progress_done / r.progress_total) * 100))
    : 0

  return (
    <div>
      <h1 className="mb-1 text-[21px] font-semibold tracking-tight text-ink">
        Scan run #{r.id}
      </h1>
      <p className="mb-5 text-ink2">
        {r.landscape_name ?? `Landscape ${r.landscape_id}`}
        {r.system_label && <> · <span className="font-mono">{r.system_label}</span></>}
        {' · '}{stamp(r.started_at)}
        {' · '}
        <span className="pill st" style={{ color: STATUS_COLOR[r.status] }}>{r.status}</span>
      </p>

      {/* ── the run's own outcome ─────────────────────────────────────────── */}
      {r.status === 'failed' && (
        <div className="banner banner-bad" role="alert">
          <strong>Run failed.</strong>{' '}
          <span className="font-mono text-[12px]">{r.error ?? 'no error was recorded'}</span>
          <div className="mt-1.5 text-ink2">
            Nothing from this run was stored. The pipeline rolls its transaction
            back before marking the run failed, so the findings elsewhere in the
            console are still the previous run's.
          </div>
        </div>
      )}

      {r.status === 'cancelled' && (
        <div className="banner banner-warn">
          <strong>Run cancelled.</strong>{' '}
          <span className="font-mono text-[12px]">{r.error ?? 'stopped on request'}</span>
          <div className="mt-1.5 text-ink2">
            A cancelled run stores nothing either — the transaction is rolled back
            before the row is marked, so the estate is exactly as the last complete
            run left it.
          </div>
        </div>
      )}

      {/* Contact with the server, reported separately from the run's status.
          Merging the two is the specific way this screen could lie: a run that
          finished ten minutes ago and a server that stopped answering both leave
          the same last-known row on screen. */}
      {pollError && (
        <div className="banner banner-warn" role="status">
          <strong>Not updating.</strong> {pollError} Showing the run as it stood at{' '}
          {clock(poll.at)}; still retrying.
        </div>
      )}

      {stalled && !pollError && (
        <div className="banner banner-warn" role="status">
          <strong>No progress since {clock(poll.changedAt)}.</strong> The scanner
          has not written anything new to this run for over{' '}
          {Math.round(STALL_MS / 60_000)} minutes. A long module looks exactly like
          this — and so does a worker that was killed mid-run, which leaves the row
          on “{r.status}” with nothing left alive to move it off. The status above
          is the last thing the scanner wrote, not a promise that it is still
          going.
        </div>
      )}

      {/* ── coverage: a correctness fix, not a nicety ─────────────────────────
          A missing export file loads as None and its checks self-skip SILENTLY,
          so a partial upload otherwise produces a clean-looking report over a
          fraction of the estate. The manifest is how the run says what it could
          not see, and it is why this banner sits above the counts rather than
          under a tab. */}
      {cov.summary && (
        <div className={`banner ${covDegraded ? 'banner-warn' : 'banner-info'}`}>
          <strong>Coverage.</strong> {cov.summary}
        </div>
      )}

      {/* ── in flight ─────────────────────────────────────────────────────── */}
      {inFlight ? (
        <div className="rounded-lg border border-line bg-panel p-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h3 className="m-0 mb-2 text-[12px] font-semibold uppercase tracking-[.06em] text-ink3">
                In progress
              </h3>
              <div className="text-ink">{PHASE[r.status]}</div>
              <div className="mt-1 text-[12px] text-ink2">
                {r.progress_total > 0
                  ? `Module ${r.progress_done} of ${r.progress_total}.`
                  : 'The module count is set once scanning starts.'}
                {' '}Last read {clock(poll.at)}.
              </div>
            </div>

            {/* "You cannot stop a running scan" is a documented complaint about the
                incumbent, so the stop button is part of the product, not a
                convenience. Hidden rather than disabled for a viewer: the API
                refuses them anyway, and a dead control is worse than none. */}
            {user.can_write && (
              <button type="button" className="btn btn-ghost" onClick={requestCancel}
                      disabled={cancelBusy || cancelling}>
                {cancelling ? 'Cancellation requested' : cancelBusy ? 'Cancelling…' : 'Cancel run'}
              </button>
            )}
          </div>

          {r.progress_total > 0 && (
            <div className="mt-3 h-1.5 overflow-hidden rounded-[3px] bg-panel2">
              <div className="h-full bg-accent" style={{ width: `${pct}%` }} />
            </div>
          )}

          {cancelling && (
            <div className="mt-3 text-[12px] text-ink2">
              The scanner checks between modules and stops cleanly, so the current
              module finishes first. A cancelled run keeps none of its findings.
            </div>
          )}
          {cancelError && (
            <div className="banner banner-bad mt-3 mb-0" role="alert">{cancelError}</div>
          )}

          <div className="mt-3 text-[12px] text-ink3">
            New, persisting, resolved and regressed counts appear when the run
            finishes. They come from one transaction that commits at the end, so a
            count taken now would read as “nothing found” rather than “not finished”.
          </div>
        </div>
      ) : diffError ? (
        <div className="banner banner-bad" role="alert">
          <strong>Results unavailable.</strong> {diffError}
        </div>
      ) : diff ? (
        <>
          <div className="grid gap-3.5 [grid-template-columns:repeat(auto-fit,minmax(210px,1fr))]">
            <Kpi label="New" value={diff.new_count} tone="text-crit" />
            <Kpi label="Persisting" value={diff.persisting} />
            <Kpi label="Resolved" value={diff.resolved} tone="text-ok" />
            <Kpi label="Regressed" value={diff.regressed_count} tone="text-high"
                 note="resolved before, back again" />
          </div>
          {diff.new_count === 0 && diff.regressed_count === 0 && r.status === 'complete' && (
            <p className="mt-3 text-[13px] text-ink2">
              Nothing new and nothing regressed in this run — read the coverage
              line above before reading that as good news.
            </p>
          )}
        </>
      ) : (
        <p className="text-ink2">Reading the results…</p>
      )}

      {/* ── regressions ──────────────────────────────────────────────────────
          Above "new" on purpose: a finding that was resolved and has come back is
          a process failure, not a backlog item. */}
      {diff && diff.regressed.length > 0 && (
        <>
          <h2 className="mt-6 mb-2.5 text-[15px] font-semibold text-ink">Regressions</h2>
          <div className="overflow-x-auto rounded-lg border border-line bg-panel">
            <table className="w-full border-collapse">
              <thead>
                <tr>
                  <th className={`${TH} w-[88px]`}>Severity</th>
                  <th className={`${TH} w-[130px]`}>Check</th>
                  <th className={TH}>Title</th>
                  <th className={`${TH} w-[90px] text-right`}>Times back</th>
                </tr>
              </thead>
              <tbody>
                {diff.regressed.map((f) => (
                  <tr key={f.id} className="hover:bg-panel2">
                    <td className={TD}><Sev value={f.severity} /></td>
                    <td className={`${TD} font-mono text-[12px]`}>
                      <Link className="text-accent hover:underline" to={`/findings/${f.id}`}>
                        {f.check_id}
                      </Link>
                    </td>
                    <td className={TD}>{f.title}</td>
                    <td className={`${TD} text-right font-mono`}>{f.regression_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {/* ── new in this run ──────────────────────────────────────────────── */}
      {diff && diff.new.length > 0 && (
        <>
          <h2 className="mt-6 mb-2.5 text-[15px] font-semibold text-ink">New in this run</h2>
          <div className="overflow-x-auto rounded-lg border border-line bg-panel">
            <table className="w-full border-collapse">
              <thead>
                <tr>
                  <th className={`${TH} w-[88px]`}>Severity</th>
                  <th className={`${TH} w-[130px]`}>Check</th>
                  <th className={TH}>Title</th>
                </tr>
              </thead>
              <tbody>
                {diff.new.map((f) => (
                  <tr key={f.id} className="hover:bg-panel2">
                    <td className={TD}><Sev value={f.severity} /></td>
                    <td className={`${TD} font-mono text-[12px]`}>
                      <Link className="text-accent hover:underline" to={`/findings/${f.id}`}>
                        {f.check_id}
                      </Link>
                    </td>
                    <td className={TD}>{f.title}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {/* ── module coverage ─────────────────────────────────────────────────
          The RISE column only exists for a RISE landscape, where some sources are
          not obtainable at all (they need OS access) and a module's scope is the
          difference between "we did not check" and "nobody can check". */}
      {covModules.length > 0 && (
        <>
          <h2 className="mt-6 mb-2.5 text-[15px] font-semibold text-ink">Module coverage</h2>
          <div className="overflow-x-auto rounded-lg border border-line bg-panel">
            <table className="w-full border-collapse">
              <thead>
                <tr>
                  <th className={TH}>Module</th>
                  <th className={`${TH} w-[100px]`}>Status</th>
                  <th className={TH}>Missing input</th>
                  {rise && <th className={`${TH} w-[120px]`}>RISE scope</th>}
                </tr>
              </thead>
              <tbody>
                {covModules.map(([name, m]) => (
                  <tr key={name} className="hover:bg-panel2">
                    <td className={`${TD} font-mono text-[12px]`}>{name}</td>
                    <td className={TD}>
                      <span className="pill st"
                            style={{ color: MODULE_COLOR[m.status ?? ''] }}>
                        {m.status ?? 'unknown'}
                      </span>
                    </td>
                    <td className={`${TD} text-[12px] text-ink3`}>
                      {m.sources_missing?.length ? m.sources_missing.join(', ') : '—'}
                    </td>
                    {rise && (
                      <td className={`${TD} text-[12px] text-ink2`}>{m.rise_scope ?? '—'}</td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {/* ── module errors ───────────────────────────────────────────────────
          Surfaced in operator language rather than swallowed. A failing component
          that yields no detail anywhere is a documented complaint about the
          incumbent, which is why the traceback is kept and shown. */}
      {moduleErrors.length > 0 && (
        <>
          <h2 className="mt-6 mb-2.5 text-[15px] font-semibold text-ink">Module errors</h2>
          <div className="rounded-lg border border-line bg-panel p-4">
            {moduleErrors.map(([name, m]) => (
              <div key={name} className="mb-3 last:mb-0">
                <strong className="font-mono">{name}</strong>
                <div className="text-[12px] text-crit">{m.error}</div>
                {m.traceback && (
                  <pre className="m-0 mt-1.5 whitespace-pre-wrap font-mono text-[12px] text-ink3">
                    {m.traceback}
                  </pre>
                )}
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  )
}
