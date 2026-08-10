/*
 * Copyright (c) 2026 Krishnendu De. All Rights Reserved.
 *
 * Author : Krishnendu De
 * Coding Assistance : Claude Code
 * Code Security Assistance : Code QL
 */

import { useState, type FormEvent } from 'react'
import { useLocation, useNavigate } from 'react-router'
import { login } from '../api/client'
import { useTitle } from '../lib/title'

/**
 * Sign-in.
 *
 * WHY IT IS IN components/ RATHER THAN routes/. routes/ belongs to the screen
 * agents migrating the thirteen console screens; sign-in is part of the shell's
 * auth surface and sits with AuthGate, which is the only other thing that knows
 * what "signed in" means.
 *
 * FORM LEFT, BRAND RIGHT — and the brand panel comes SECOND in the DOM. Left and
 * right are CSS; document order is what a keyboard and a screen reader follow,
 * and the thing you came to do must precede the thing that tells you where you
 * are. On a narrow viewport the CSS moves the brand above the form, because a
 * bare username box with no branding over it is what a phishing page looks like.
 *
 * ONE ERROR MESSAGE FOR EVERY REJECTION. The server answers identically for an
 * unknown username and a wrong password and takes the same time over both;
 * splitting them here would rebuild the username oracle in the client.
 *
 * THE "NO SELF-SERVICE RESET" PARAGRAPH IS NOT FILLER. It is carried verbatim
 * from login.html because this is the one screen a locked-out person is looking
 * at, and it is the only place the product explains that the absence of a
 * "forgot my password" link is a decision rather than a missing feature — an
 * unauthenticated reset turns control of a mailbox into control of the console.
 * Without it the screen reads as unfinished and the next request is for the hole.
 */
export default function Login() {
  useTitle('Sign in')
  const navigate = useNavigate()
  const location = useLocation()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  // Where AuthGate was sending them before it found no session. Constrained to a
  // local path: an open redirect here would let a crafted link bounce a freshly
  // authenticated user off-site, which is the same hole server/app.py closes on
  // the Jinja login's ?next=.
  const raw = (location.state as { from?: string } | null)?.from
  const next = raw && raw.startsWith('/') && !raw.startsWith('//') ? raw : '/'

  async function submit(event: FormEvent) {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      const user = await login(username, password)
      // A generated password is a handover credential, not a chosen one — the
      // server gates every other route until it is replaced, so go straight to
      // the screen that replaces it rather than to a console that will 403.
      navigate(user.must_change_password ? '/account' : next, { replace: true })
    } catch {
      setError('Invalid credentials')
      setBusy(false)
    }
  }

  return (
    <div className="auth">
      <div className="auth-form">
        <div>
          <h1 className="text-[21px] font-semibold tracking-tight text-ink mb-1">Sign in</h1>
          <p className="text-ink2 mb-5 text-[13px]">
            SAP threat, vulnerability and GRC posture — assessed offline, tracked
            to closure.
          </p>

          <form onSubmit={submit}>
            <label className="block text-[12px] text-ink3 mb-1" htmlFor="username">
              Username
            </label>
            <input
              id="username" className="field mb-3" autoComplete="username" required
              autoFocus value={username} onChange={(e) => setUsername(e.target.value)}
            />

            <label className="block text-[12px] text-ink3 mb-1" htmlFor="password">
              Password
            </label>
            <input
              id="password" type="password" className="field mb-4"
              autoComplete="current-password" required
              value={password} onChange={(e) => setPassword(e.target.value)}
            />

            {error && <div className="banner banner-bad" role="alert">{error}</div>}

            <button type="submit" className="btn w-full" disabled={busy}>
              {busy ? 'Signing in…' : 'Sign in'}
            </button>
          </form>

          <p className="mt-3.5 text-[12px] text-ink3">
            Forgotten it? There is no self-service reset — an unauthenticated reset
            is a way in. Ask an administrator, who can issue you a new one from
            their <strong className="font-[650]">Your account</strong> page.
          </p>
        </div>
      </div>

      <div className="auth-brand">
        {/* Intrinsic width/height are the asset's real pixels, so the panel
            reserves its space before the image loads and the form does not jump
            sideways under a cursor that is already in the username box. Keep
            these in step with tools/build_brand_assets.py — the lockup is 1100
            wide by construction and the height follows the master's crop. */}
        <img src="/static/monitorrisk-logo.png" width={1100} height={401}
             alt="MonitorRisk — SAP Threat, Vulnerability, Governance &amp; Risk Quantification" />
      </div>
    </div>
  )
}
