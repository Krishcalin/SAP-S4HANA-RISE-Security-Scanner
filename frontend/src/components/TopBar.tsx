/*
 * Copyright (c) 2026 Krishnendu De. All Rights Reserved.
 *
 * Author : Krishnendu De
 * Coding Assistance : Claude Code
 * Code Security Assistance : Code QL
 */

import { useState } from 'react'
import { useNavigate } from 'react-router'
import { logout } from '../api/client'
import { useSession } from '../lib/session'

/**
 * Who you are, and the way out.
 *
 * SIGNING OUT AWAITS THE SERVER. `logout()` throws on a non-2xx, so a failed
 * sign-out is reported instead of being mistaken for a successful one — the
 * session would otherwise survive its full window while the user stands in front
 * of a login form believing they had left. The button stays disabled for the
 * duration; `logout()` carries its own 5-second bound, so this cannot hang.
 *
 * NAVIGATION IS A FULL RELOAD, not a router push. Every screen below has already
 * cached whatever it fetched, and a client-side transition to /login leaves that
 * in memory. `location.assign` throws the whole document away, which is the only
 * version of "signed out" that is true of the browser as well as the server.
 */
export function TopBar() {
  const { user } = useSession()
  const navigate = useNavigate()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function signOut() {
    setBusy(true)
    setError('')
    try {
      await logout()
      window.location.assign(`${import.meta.env.BASE_URL}login`)
    } catch {
      setBusy(false)
      setError('Sign-out failed — your session may still be open.')
    }
  }

  return (
    <header className="h-[54px] shrink-0 flex items-center gap-4 px-5 border-b border-line bg-panel">
      <div className="flex-1" />
      {error && <span className="text-[12px] text-crit">{error}</span>}
      <button
        type="button"
        onClick={() => navigate('/account')}
        className="text-[13px] text-ink2 hover:text-ink"
        title="Account and password"
      >
        {user.display_name}
        <span className="ml-2 rounded-full border border-line bg-panel2 px-2 py-0.5 text-[11px] uppercase tracking-wider text-ink3">
          {user.role}
        </span>
      </button>
      <button type="button" className="btn btn-ghost" onClick={signOut} disabled={busy}>
        {busy ? 'Signing out…' : 'Sign out'}
      </button>
    </header>
  )
}
