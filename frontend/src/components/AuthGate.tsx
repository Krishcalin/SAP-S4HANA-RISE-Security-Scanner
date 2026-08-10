/*
 * Copyright (c) 2026 Krishnendu De. All Rights Reserved.
 *
 * Author : Krishnendu De
 * Coding Assistance : Claude Code
 * Code Security Assistance : Code QL
 */

import { useCallback, useEffect, useState } from 'react'
import { Navigate, useLocation } from 'react-router'
import { me } from '../api/client'
import type { Me } from '../api/types'
import { SessionContext } from '../lib/session'

/**
 * Resolves the session before the console renders, and provides it below.
 *
 * WHY THIS EXISTS AT ALL, GIVEN THE SERVER ALREADY REFUSES. The API is the
 * security boundary: every route resolves a user from the session cookie and an
 * unauthenticated one is refused. This gate is so a signed-out visitor sees a
 * sign-in form instead of a console rendering a screenful of failed requests.
 * Nothing here is a control — deleting it would leak no data, only dignity.
 *
 * A NETWORK OR 500 ERROR IS NOT AN AUTHENTICATED STATE. `me()` returns null only
 * on a 401 and throws on everything else, and the catch below sends the user to
 * the sign-in screen. That is the honest answer: we do not know who they are.
 *
 * THE FORCED-PASSWORD REDIRECT MIRRORS THE SERVER'S, it does not implement it.
 * server/api_auth.py holds a forced account at the gate for every route except
 * the ones that let it out, so a user who ignored this would get a 403 with
 * `change_at` from the first screen they opened. Doing it here as well is what
 * turns that into a sentence instead of six broken panels.
 */
export default function AuthGate({ children }: { children: React.ReactNode }) {
  const location = useLocation()
  const [state, setState] = useState<'checking' | 'in' | 'out'>('checking')
  const [user, setUser] = useState<Me | null>(null)

  const apply = useCallback((u: Me | null) => {
    setUser(u)
    setState(u ? 'in' : 'out')
  }, [])

  /** Exposed as `reload` on the session. Rejects on anything but a 401, so a
   *  caller that cares can report it; ignoring it leaves the old user in place,
   *  which is the safe direction. */
  const reload = useCallback(async () => { apply(await me()) }, [apply])

  useEffect(() => {
    let cancelled = false
    me()
      .then((u) => { if (!cancelled) apply(u) })
      .catch(() => { if (!cancelled) apply(null) })
    return () => { cancelled = true }
    // Deliberately once per mount, not per navigation. Re-checking on every route
    // change costs a request per click and buys nothing: a session that expires
    // mid-visit surfaces as a 401 from the screen's own call, which is where the
    // user actually is.
  }, [apply])

  if (state === 'checking') {
    // Deliberately blank rather than a spinner: the check is one local request,
    // and chrome that appears and vanishes reads worse than a beat of nothing.
    return <div className="auth-checking" aria-busy="true" />
  }
  if (state === 'out' || user === null) {
    // `state` carries where they were going, so signing in lands them there
    // rather than dumping them on the dashboard.
    return <Navigate to="/login" replace state={{ from: location.pathname + location.search }} />
  }
  if (user.must_change_password && location.pathname !== '/account') {
    return <Navigate to="/account" replace />
  }
  return (
    <SessionContext.Provider value={{ user, reload }}>
      {children}
    </SessionContext.Provider>
  )
}
