import { useCallback, useEffect, useState, type FormEvent } from 'react'
import {
  ApiError, totpBegin, totpConfirm, totpDisable, totpRegenerateRecovery, totpStatus,
} from '../api/client'
import type { TotpEnrolment, TotpStatus } from '../api/types'

/**
 * Two-factor authentication, on the account screen.
 *
 * THREE WAYS TO ENROL, AND NONE OF THEM IS OPTIONAL DECORATION. The QR is the
 * fastest; the `otpauth://` link is a LINK, so tapping it on the phone itself
 * opens the authenticator with nothing to scan; and the typed secret works when
 * the camera is unavailable or the screen is being shared. The server may return
 * an empty `qr_svg` — the encoder degrades rather than 500s — so the other two
 * must always be present, not revealed as a fallback.
 *
 * NOTHING IS LIVE UNTIL A CODE COMES BACK. `begin` mints a PENDING secret that
 * cannot satisfy a login, so a failed scan or a mistyped secret does not enrol
 * and cannot lock anyone out. That is why the flow ends with typing a code rather
 * than with a "Done" button.
 *
 * THE RECOVERY CODES ARE SHOWN EXACTLY ONCE. They are stored only as hashes, so
 * neither this screen nor an administrator can ever show them again — the same
 * contract as a generated password. The wording says so plainly, because a user
 * who assumes they can come back for them later is the user who gets locked out.
 */
export function TotpPanel({ forced }: { forced: boolean }) {
  const [status, setStatus] = useState<TotpStatus | null>(null)
  const [loadError, setLoadError] = useState('')

  const [enrolment, setEnrolment] = useState<TotpEnrolment | null>(null)
  const [codes, setCodes] = useState<string[] | null>(null)

  const [current, setCurrent] = useState('')
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [note, setNote] = useState('')

  const refresh = useCallback(async () => {
    setStatus(await totpStatus())
  }, [])

  useEffect(() => {
    let cancelled = false
    totpStatus()
      .then((s) => { if (!cancelled) setStatus(s) })
      .catch((e: unknown) => {
        if (!cancelled) {
          setLoadError(e instanceof ApiError ? e.message
            : 'Could not read your two-factor status.')
        }
      })
    return () => { cancelled = true }
  }, [])

  function clear() {
    setCurrent('')
    setCode('')
    setError('')
  }

  async function run(action: () => Promise<void>) {
    setBusy(true)
    setError('')
    setNote('')
    try {
      await action()
    } catch (e) {
      setError(e instanceof ApiError ? e.message : 'That did not work.')
    } finally {
      setBusy(false)
    }
  }

  const begin = (e: FormEvent) => {
    e.preventDefault()
    return run(async () => {
      setEnrolment(await totpBegin(current))
      setCode('')
    })
  }

  const confirm = (e: FormEvent) => {
    e.preventDefault()
    return run(async () => {
      const r = await totpConfirm(current, code)
      setCodes(r.recovery_codes)
      setEnrolment(null)
      clear()
      await refresh()
    })
  }

  const disable = (e: FormEvent) => {
    e.preventDefault()
    return run(async () => {
      await totpDisable(current, code)
      clear()
      setNote('Two-factor authentication is off. Your recovery codes were '
        + 'invalidated with it.')
      await refresh()
    })
  }

  const regenerate = (e: FormEvent) => {
    e.preventDefault()
    return run(async () => {
      const r = await totpRegenerateRecovery(current, code)
      setCodes(r.recovery_codes)
      clear()
      await refresh()
    })
  }

  if (loadError) {
    return <div className="banner banner-bad" role="alert">{loadError}</div>
  }
  if (!status) return <p className="text-[13px] text-ink3">Loading…</p>

  // ── the codes, shown once ────────────────────────────────────────────────
  if (codes) {
    return (
      <div>
        <div className="banner banner-warn">
          <strong className="font-semibold">Save these now.</strong> They are stored
          only as hashes, so this is the one time they can be shown — not by this
          screen and not by an administrator. Each works once, in place of a code
          from your app.
        </div>
        <ul className="my-3 grid grid-cols-2 gap-1.5 font-mono text-[13px]">
          {codes.map((c) => <li key={c} className="text-ink">{c}</li>)}
        </ul>
        <button className="btn" onClick={() => { setCodes(null); void refresh() }}>
          I have saved them
        </button>
      </div>
    )
  }

  // ── mid-enrolment ────────────────────────────────────────────────────────
  if (enrolment) {
    return (
      <form onSubmit={confirm}>
        <p className="mb-3 text-[13px] text-ink2">
          Scan this with Microsoft Authenticator, Google Authenticator, Authy or
          1Password — then type the six digits it shows to finish. Nothing is
          active until you do.
        </p>
        {enrolment.qr_svg && (
          <div
            className="mb-3 inline-block rounded-[6px] bg-white p-2"
            /* The SVG is generated by server/qr.py from numeric coordinates and
               two fixed colour constants; no user-controlled text reaches its
               markup — the account name is encoded into the MODULE PATTERN, not
               into the document. tests/test_qr.py asserts it contains no script,
               no href and no external reference. */
            dangerouslySetInnerHTML={{ __html: enrolment.qr_svg }}
          />
        )}
        <p className="mb-1 text-[12px] text-ink3">Can’t scan it?</p>
        <p className="mb-3 text-[13px]">
          <a className="text-accent" href={enrolment.uri}>Open in your authenticator</a>
          {' · or enter this key: '}
          <code className="font-mono text-ink">{enrolment.formatted_secret}</code>
        </p>

        <label className="block text-[12px] text-ink3 mb-1" htmlFor="totp-confirm">
          Code from the app
        </label>
        <input
          id="totp-confirm" className="field mb-3" required autoFocus
          value={code} onChange={(e) => setCode(e.target.value)}
          autoComplete="one-time-code" inputMode="numeric" placeholder="123456"
        />
        {error && <div className="banner banner-bad" role="alert">{error}</div>}
        <div className="flex gap-2">
          <button type="submit" className="btn" disabled={busy}>
            {busy ? 'Checking…' : 'Turn on'}
          </button>
          <button type="button" className="btn btn-ghost"
                  onClick={() => { setEnrolment(null); clear() }}>
            Cancel
          </button>
        </div>
        <p className="mt-3 text-[12px] text-ink3">
          Turning this on signs you out everywhere else — any session opened before
          the second factor existed was opened with one credential.
        </p>
      </form>
    )
  }

  // ── enabled ──────────────────────────────────────────────────────────────
  if (status.enabled) {
    const none = status.recovery_codes_left === 0
    return (
      <div>
        <p className="mb-3 text-[13px] text-ink2">
          <span className="pill st-resolved">On</span>{' '}
          Sign-in asks for a code from your authenticator app.
        </p>
        <div className={none ? 'banner banner-bad' : 'banner'}>
          {none ? (
            <>
              <strong className="font-semibold">No recovery codes left.</strong> If
              you lose your phone now, only an administrator running{' '}
              <code className="font-mono">server.cli totp-disable</code> on the host
              can get you back in. Generate a new set below.
            </>
          ) : (
            <>{status.recovery_codes_left} recovery code
              {status.recovery_codes_left === 1 ? '' : 's'} left.</>
          )}
        </div>
        {note && <div className="banner banner-ok" role="status">{note}</div>}

        <form className="mt-3" onSubmit={regenerate}>
          <div className="grid gap-2 sm:grid-cols-2">
            <input className="field" type="password" required placeholder="Current password"
                   autoComplete="current-password"
                   value={current} onChange={(e) => setCurrent(e.target.value)} />
            <input className="field" required placeholder="Code, or a recovery code"
                   autoComplete="one-time-code"
                   value={code} onChange={(e) => setCode(e.target.value)} />
          </div>
          {error && <div className="banner banner-bad mt-2" role="alert">{error}</div>}
          <div className="mt-2 flex gap-2">
            <button type="submit" className="btn btn-ghost" disabled={busy}>
              New recovery codes
            </button>
            <button type="button" className="btn btn-ghost" disabled={busy}
                    onClick={(e) => disable(e as unknown as FormEvent)}>
              Turn off
            </button>
          </div>
          <p className="mt-2 text-[12px] text-ink3">
            Both need your password and one code — a stolen session must not be
            enough to remove or replace your second factor. A recovery code is
            accepted in the code box if your authenticator is gone.
          </p>
        </form>
      </div>
    )
  }

  // ── not enrolled ─────────────────────────────────────────────────────────
  return (
    <form onSubmit={begin}>
      <p className="mb-3 text-[13px] text-ink2">
        Add a one-time code from an authenticator app to your sign-in. A stolen
        password stops being enough on its own.
      </p>
      {forced ? (
        <div className="banner banner-warn">
          Choose your own password first. A second factor must not be bound to a
          password that was generated for you and printed to a terminal.
        </div>
      ) : (
        <>
          <label className="block text-[12px] text-ink3 mb-1" htmlFor="totp-current">
            Current password
          </label>
          <input
            id="totp-current" type="password" className="field mb-3" required
            autoComplete="current-password"
            value={current} onChange={(e) => setCurrent(e.target.value)}
          />
          {error && <div className="banner banner-bad" role="alert">{error}</div>}
          {note && <div className="banner banner-ok" role="status">{note}</div>}
          <button type="submit" className="btn" disabled={busy}>
            {busy ? 'Starting…' : 'Set up two-factor authentication'}
          </button>
        </>
      )}
    </form>
  )
}
