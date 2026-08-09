import { useEffect, useState } from 'react'
import { Link, Navigate, useParams } from 'react-router'
import { ApiError, view } from '../api/client'
import type { ResolvedView } from '../api/types'
import { useTitle } from '../lib/title'

/**
 * A saved view: /v/:slug — the durable, permission-scoped URL per audience.
 *
 * IT RESOLVES TO FILTERS AND THEN GETS OUT OF THE WAY. `/api/views/{slug}`
 * returns the stored FILTERS, never rows, and this screen replays them into the
 * address bar of the screen that owns them. That indirection is the property
 * that makes a shared link safe: the receiving screen re-runs the query under
 * its own caller's row scope, so two people following the same URL each see only
 * the systems they are entitled to. A saved view can never widen access, and it
 * must not start returning data of its own or that stops being true.
 *
 * IT IS THE SPA HALF OF A 303. server/app.py's `open_view` answers the same URL
 * with a redirect to /findings?… or /trend?…; this does the client-side
 * equivalent so a link works identically in whichever console the reader lands
 * in while both are live.
 *
 * WHY `replace`. The history entry for /v/:slug must not survive the
 * navigation. Left in place, pressing Back from the findings queue would land on
 * this screen, which would immediately resolve and push the reader forward
 * again — a Back button that does nothing.
 *
 * IT HAS NO NAV ENTRY AND MUST NOT GAIN ONE: the slug is parameterised, so there
 * is no single URL to put in a menu. Sidebar.tsx fetches the view list at mount
 * and renders a link each, which is how these are reached by clicking.
 */

/** The same map `open_view` uses for its 303, including its treatment of a
 *  `coverage` view — which falls through to /findings there because the coverage
 *  screen takes no filters. Mirrored rather than quietly corrected: the two
 *  consoles are live at once, and the same saved link opening a different screen
 *  depending on which one you are in is worse than a target nobody uses. */
const TARGET: Record<string, string> = { findings: '/findings', trend: '/trend' }

function destination(resolved: ResolvedView): string {
  const target = TARGET[resolved.kind] ?? '/findings'
  const params = new URLSearchParams()
  for (const [key, value] of Object.entries(resolved.filters ?? {})) {
    // Same emptiness test as the server's urlencode filter. An empty value is
    // not a filter, and forwarding `state=` would look like a deliberate
    // selection of nothing.
    if (value === null || value === undefined || value === '') continue
    params.set(key, String(value))
  }
  const query = params.toString()
  return query ? `${target}?${query}` : target
}

/** Branched on the status, never on the message text — `missing` reads very
 *  differently to the reader than "the server broke", and matching on wording is
 *  how that distinction gets lost the first time somebody rephrases a detail. */
type Failure = { kind: 'missing' } | { kind: 'other'; message: string }

export function SavedView() {
  useTitle('Saved view')
  const { slug } = useParams<{ slug: string }>()
  const [resolved, setResolved] = useState<ResolvedView | null>(null)
  const [failure, setFailure] = useState<Failure | null>(null)

  useEffect(() => {
    if (!slug) return
    let cancelled = false
    // Reset on a slug change: clicking a second saved view while this one is on
    // screen would otherwise carry the first one's error, or redirect using the
    // filters of the view the reader just navigated away from.
    setResolved(null)
    setFailure(null)
    view(slug)
      .then((r) => { if (!cancelled) setResolved(r) })
      .catch((e: unknown) => {
        if (cancelled) return
        // 404 covers BOTH "no such slug" and "a private view of somebody
        // else's" — server/queries.py `get_view` filters on
        // `(is_shared OR created_by = me)`, so a view you may not see is
        // indistinguishable from one that does not exist. That is deliberate,
        // and answering "you are not allowed to see it" here would undo it by
        // confirming the slug exists.
        setFailure(
          e instanceof ApiError && e.status === 404
            ? { kind: 'missing' }
            : { kind: 'other',
                message: e instanceof ApiError ? e.message : 'Could not open that view.' },
        )
      })
    return () => { cancelled = true }
  }, [slug])

  if (!slug) return <Navigate to="/" replace />
  if (resolved) return <Navigate to={destination(resolved)} replace />

  if (failure) {
    return (
      <div className="max-w-xl">
        <h1 className="mb-1 text-[21px] font-semibold tracking-tight text-ink">
          {failure.kind === 'missing' ? 'No such saved view' : 'Could not open that view'}
        </h1>
        {failure.kind === 'missing' ? (
          <p className="mb-4 text-[13px] text-ink2">
            <code className="font-mono text-ink">/v/{slug}</code> does not name a view
            you can open. Either it was deleted, or it was saved privately by somebody
            else — a view is visible to its author and, when it is shared, to everyone.
          </p>
        ) : (
          <p className="mb-4 text-[13px] text-ink2">{failure.message}</p>
        )}
        <Link className="btn btn-ghost inline-block no-underline" to="/">
          Back to the dashboard
        </Link>
      </div>
    )
  }

  // One local request, and then a redirect. A spinner that appears and vanishes
  // reads worse than a line of text, which is the same call AuthGate makes.
  return <div className="text-[13px] text-ink2">Opening saved view…</div>
}
