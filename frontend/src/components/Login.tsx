/*
 * Copyright (c) 2026 Krishnendu De. All Rights Reserved.
 *
 * Author : Krishnendu De
 * Coding Assistance : Claude Code
 * Code Security Assistance : Code QL
 */

import { useState, type FormEvent } from 'react'
import { useLocation, useNavigate } from 'react-router'
import { ApiError, login } from '../api/client'
import { useTitle } from '../lib/title'
import { LogIn } from 'lucide-react'

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
  // The code field appears only after the SERVER says this account has a factor,
  // and the server only says so once the password is correct. Rendering it up
  // front, or deciding locally whether to show it, would leak which accounts have
  // 2FA to anyone who can type a username.
  const [needsCode, setNeedsCode] = useState(false)
  const [code, setCode] = useState('')

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
      const user = await login(username, password, code)
      // A generated password is a handover credential, not a chosen one — the
      // server gates every other route until it is replaced, so go straight to
      // the screen that replaces it rather than to a console that will 403.
      //
      // Someone who just spent a recovery code is sent to /account regardless:
      // they have one fewer way back and no working authenticator, and the
      // account screen is where both are fixed. Losing that prompt is how a
      // person ends up with zero codes and a dead phone.
      const target = user.used_recovery_code ? '/account' : next
      navigate(user.must_change_password ? '/account' : target, { replace: true })
    } catch (e) {
      if (e instanceof ApiError && e.totpRequired) {
        // Not a failure to show as one: the password was right. Reveal the field
        // and keep what they typed.
        setNeedsCode(true)
        setError('')
      } else {
        setError('Invalid credentials')
        // Clear the code but NOT the password: a wrong six digits should not make
        // somebody retype a long password, and the server holds a separate budget
        // for each so this costs them nothing extra.
        setCode('')
      }
      setBusy(false)
    }
  }

  return (
    <div className="auth">
      <div className="auth-form">
        <div>
          <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2 mb-1">
        <LogIn size={22} className="text-accent shrink-0" />Sign in</h1>
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

            {needsCode && (
              <>
                <label className="block text-[12px] text-ink3 mb-1" htmlFor="totp">
                  Authentication code
                </label>
                <input
                  id="totp" className="field mb-1" required autoFocus
                  value={code} onChange={(e) => setCode(e.target.value)}
                  // `one-time-code` is what lets a phone offer the code from the
                  // notification. `inputMode` is text, not numeric, because this
                  // field also takes a recovery code.
                  autoComplete="one-time-code" inputMode="text"
                  placeholder="123456"
                />
                <p className="mb-4 text-[12px] text-ink3">
                  From your authenticator app. Lost your phone? Enter one of your
                  recovery codes here instead.
                </p>
              </>
            )}

            {error && <div className="banner banner-bad" role="alert">{error}</div>}

            <button type="submit" className="btn w-full" disabled={busy}>
              {busy ? 'Signing in…' : needsCode ? 'Verify' : 'Sign in'}
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
