import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { ApiError, account, changePassword, resetUserPassword } from '../api/client'
import { useSession } from '../lib/session'
import { useTitle } from '../lib/title'
import type { AccountInfo, GeneratedPassword } from '../api/types'

/**
 * Your account: your own password, and — for an admin — issuing a new one to
 * somebody else. Ported from server/templates/account.html.
 *
 * THERE IS DELIBERATELY NO SELF-SERVICE RESET. An unauthenticated "forgot my
 * password" flow is a way in: it turns control of a mailbox, or of whatever
 * channel carries the link, into control of the console. So the only two paths
 * to a new password are the form below (which requires the current one) and an
 * admin issuing one; the last resort is the host, where whoever runs the
 * container already has full access anyway. That framing is the product's, not
 * an omission, and the copy on this screen says so out loud.
 *
 * THE CURRENT PASSWORD IS REQUIRED EVEN THOUGH YOU ARE SIGNED IN, because a
 * stolen session must not be enough to take the account over permanently. The
 * server enforces it; this screen only asks.
 *
 * AN ADMIN RESET GENERATES A PASSWORD, IT NEVER CHOOSES ONE. An admin who can
 * set a password they know can impersonate a user and leave nothing that user
 * could tell apart from their own activity. The generated value comes back in
 * the response body and exists nowhere else — not in the audit log, not in a
 * URL — so it is held in component state, shown once, and dismissable. Do not
 * "helpfully" persist it, put it in the address bar, or mail it from here.
 */

/** Timestamps as the server states them, not as the browser re-reads them.
 *
 *  The API sends `datetime.isoformat()`. Handing that to `new Date()` re-zones
 *  it — a naive stamp is parsed as browser-local, an offset one is converted —
 *  so this screen and the Jinja page, which strftimes the same value with no
 *  conversion, would disagree by hours about the same sign-in while both
 *  consoles are live. Slicing the string keeps the two identical. */
function stamp(iso: string | null, absent = '—'): string {
  if (!iso) return absent
  const parts = /^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2})/.exec(iso)
  return parts ? `${parts[1]} ${parts[2]}` : iso
}

function Card({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-[8px] border border-line bg-panel p-4">
      <h3 className="mb-3 text-[12px] font-semibold uppercase tracking-[.06em] text-ink3">
        {title}
      </h3>
      {children}
    </div>
  )
}

export function Account() {
  useTitle('Account')
  // `reload` re-reads /api/auth/me. A password change clears
  // must_change_password, and a console still holding the old value keeps the
  // account gated by AuthGate after the thing that ungates it has happened.
  const { reload } = useSession()

  const [info, setInfo] = useState<AccountInfo | null>(null)
  const [loadError, setLoadError] = useState('')

  const [current, setCurrent] = useState('')
  const [new1, setNew1] = useState('')
  const [new2, setNew2] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [changed, setChanged] = useState(false)

  const [resetting, setResetting] = useState<number | null>(null)
  const [adminError, setAdminError] = useState('')
  const [generated, setGenerated] = useState<GeneratedPassword | null>(null)

  const refresh = useCallback(async () => {
    setInfo(await account())
  }, [])

  useEffect(() => {
    let cancelled = false
    account()
      .then((a) => { if (!cancelled) setInfo(a) })
      .catch((e: unknown) => {
        if (!cancelled) {
          setLoadError(e instanceof ApiError ? e.message : 'Could not load your account.')
        }
      })
    return () => { cancelled = true }
  }, [])

  async function submit(event: FormEvent) {
    event.preventDefault()
    setBusy(true)
    setError('')
    setChanged(false)
    try {
      await changePassword(current, new1, new2)
      // Cleared on success only. A rejected attempt keeps what was typed, so a
      // mistyped confirmation costs one field rather than all three.
      setCurrent(''); setNew1(''); setNew2('')
      setChanged(true)
      // The password HAS changed by this point. Both refreshes are cosmetic —
      // the session count and the forced banner — so a failure here must not be
      // reported as a failed change, which is why neither is allowed to throw
      // past this handler. The worst case is a stale panel and a page reload.
      try { await refresh() } catch { /* see above */ }
      try { await reload() } catch { /* see above */ }
    } catch (e: unknown) {
      // The server's own wording — "Current password is incorrect.", "The new
      // passwords do not match.", "The new password must differ from the current
      // one." — surfaced verbatim. Re-deriving these rules in the client is how
      // the two surfaces drift into accepting different passwords.
      setError(e instanceof ApiError ? e.message : 'Could not change the password.')
    } finally {
      setBusy(false)
    }
  }

  async function reset(userId: number) {
    setResetting(userId)
    setAdminError('')
    setGenerated(null)
    try {
      setGenerated(await resetUserPassword(userId))
      // The reset flipped that row's must_change_password and dropped every one
      // of their sessions; re-read so the State column says so.
      try { await refresh() } catch { /* the reset still happened */ }
    } catch (e: unknown) {
      setAdminError(e instanceof ApiError ? e.message : 'Could not reset that password.')
    } finally {
      setResetting(null)
    }
  }

  if (loadError) {
    return (
      <div className="max-w-xl">
        <h1 className="mb-1 text-[21px] font-semibold tracking-tight text-ink">Your account</h1>
        <div className="banner banner-bad" role="alert">{loadError}</div>
      </div>
    )
  }
  if (!info) return <div className="text-[13px] text-ink2">Loading…</div>

  // The freshly fetched user rather than the session's copy: this screen is the
  // one place that changes those fields, and rendering the value AuthGate
  // resolved at mount would show the old "Password set" straight after setting it.
  const user = info.user

  return (
    <>
      <h1 className="mb-1 text-[21px] font-semibold tracking-tight text-ink">Your account</h1>
      <p className="mb-5 text-[13px] text-ink2">
        {user.display_name} · {user.role}
      </p>

      {info.forced && (
        // The bootstrap admin arrives here and cannot leave until the password
        // changes. `create-user --generate` prints a password to a terminal,
        // where it survives in scrollback, in `docker compose logs` and in
        // whatever recorded the session — a machine-generated password is a
        // handover credential, not a chosen one.
        <div className="banner banner-bad">
          <strong>Choose a password before continuing.</strong>{' '}
          This account is still using a password that was generated for it and printed
          to a terminal, so it exists in scrollback and in logs. The rest of the console
          is unavailable until it is replaced.
        </div>
      )}

      {error && <div className="banner banner-bad" role="alert">{error}</div>}

      {changed && (
        <div className="banner banner-ok" role="status">
          <strong>Password changed.</strong> Every other session for this account was
          signed out — if a credential had leaked, that is what stops it being useful.
        </div>
      )}

      <div className="grid grid-cols-[repeat(auto-fit,minmax(340px,1fr))] gap-3.5">
        <form className="rounded-[8px] border border-line bg-panel p-4" onSubmit={submit}>
          <h3 className="mb-3 text-[12px] font-semibold uppercase tracking-[.06em] text-ink3">
            Change password
          </h3>

          <label className="block text-[12px] text-ink3" htmlFor="current">
            Current password
          </label>
          <input
            id="current" type="password" className="field mb-3 mt-1" required
            autoComplete="current-password"
            value={current} onChange={(e) => setCurrent(e.target.value)}
          />

          <label className="block text-[12px] text-ink3" htmlFor="new1">New password</label>
          {/* minLength 12 is the FORM's rule and matches the Jinja form's
              attribute exactly. The server does not enforce a length, so the two
              consoles must at least ask for the same thing; strengthening it
              here alone would mean a password the SPA refuses and the other page
              accepts. */}
          <input
            id="new1" type="password" className="field mt-1" required minLength={12}
            autoComplete="new-password"
            value={new1} onChange={(e) => setNew1(e.target.value)}
          />
          <div className="mb-3 mt-1 text-[12px] text-ink3">At least 12 characters.</div>

          <label className="block text-[12px] text-ink3" htmlFor="new2">
            Confirm new password
          </label>
          <input
            id="new2" type="password" className="field mb-4 mt-1" required minLength={12}
            autoComplete="new-password"
            value={new2} onChange={(e) => setNew2(e.target.value)}
          />

          <button type="submit" className="btn" disabled={busy}>
            {busy ? 'Changing…' : 'Change password'}
          </button>
          <p className="mt-3 text-[12px] text-ink3">
            The current password is required even though you are already signed in — a
            stolen session should not be enough to take the account over permanently.
          </p>
        </form>

        <Card title="Details">
          <dl className="m-0 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5">
            <dt className="text-[12px] text-ink3">Username</dt>
            <dd className="m-0 font-mono text-[.92em]">{user.username}</dd>

            <dt className="text-[12px] text-ink3">Role</dt>
            <dd className="m-0">{user.role}</dd>

            <dt className="text-[12px] text-ink3">Last sign-in</dt>
            <dd className="m-0">{stamp(user.last_login_at)}</dd>

            <dt className="text-[12px] text-ink3">Password set</dt>
            <dd className="m-0">
              {stamp(user.password_changed_at, 'never — still the original')}
            </dd>

            <dt className="text-[12px] text-ink3">Active sessions</dt>
            <dd className="m-0">{info.sessions}</dd>
          </dl>
          <p className="mt-3.5 text-[12px] text-ink3">
            Locked out of every admin account? Reset one from the host, where whoever
            runs the container already has full access anyway:<br />
            <span className="font-mono text-[.92em]">
              docker compose exec app python -m server.cli set-password &lt;user&gt; --generate
            </span>
          </p>
        </Card>
      </div>

      {/* Hidden while forced, exactly as the template hides it: an account held
          at the gate has one job, and offering it the administration of other
          people's credentials first is the wrong order. `users` is empty for a
          non-admin anyway — the server returns an empty list rather than a 403,
          so the rest of the screen is never collateral damage of a permission
          somebody does not have. */}
      {user.is_admin && !info.forced && (
        <>
          <h2 className="mb-2.5 mt-6 text-[15px] text-ink">Users</h2>

          {/* Admins reset other people's passwords by GENERATING one, never by
              choosing it: an admin who can set a known password can impersonate
              a user and leave no trace the user could distinguish from their own
              activity. */}
          <div className="banner banner-info">
            A reset mints a new password and signs that user out everywhere. You hand it
            over once; they are then required to replace it at next sign-in.
          </div>

          {adminError && <div className="banner banner-bad" role="alert">{adminError}</div>}

          <div className="overflow-x-auto rounded-[8px] border border-line bg-panel">
            <table className="w-full border-collapse">
              <thead>
                <tr>
                  <th className="border-b border-line px-2.5 py-2 text-left text-[11px] font-semibold uppercase tracking-[.05em] text-ink3">
                    User
                  </th>
                  <th className="w-[90px] border-b border-line px-2.5 py-2 text-left text-[11px] font-semibold uppercase tracking-[.05em] text-ink3">
                    Role
                  </th>
                  <th className="w-[150px] border-b border-line px-2.5 py-2 text-left text-[11px] font-semibold uppercase tracking-[.05em] text-ink3">
                    Last sign-in
                  </th>
                  {/* An account that has never SET a password is still holding
                      the generated one, which lives in terminal scrollback and
                      in the container logs. `must_change_password` does not say
                      that — it is cleared the moment somebody is let through —
                      so this column is the only place an admin can see which
                      handover credentials are still in use. */}
                  <th className="w-[150px] border-b border-line px-2.5 py-2 text-left text-[11px] font-semibold uppercase tracking-[.05em] text-ink3">
                    Password set
                  </th>
                  <th className="w-[120px] border-b border-line px-2.5 py-2 text-left text-[11px] font-semibold uppercase tracking-[.05em] text-ink3">
                    State
                  </th>
                  <th className="w-[110px] border-b border-line px-2.5 py-2" />
                </tr>
              </thead>
              <tbody>
                {info.users.map((u) => (
                  <tr key={u.id} className="hover:bg-panel2">
                    <td className="border-b border-line px-2.5 py-2.5 align-top font-mono text-[12px]">
                      {u.username}
                    </td>
                    <td className="border-b border-line px-2.5 py-2.5 align-top text-[12px]">
                      {u.role}
                    </td>
                    <td className="border-b border-line px-2.5 py-2.5 align-top text-[12px] text-ink2">
                      {stamp(u.last_login_at, 'never')}
                    </td>
                    <td className="border-b border-line px-2.5 py-2.5 align-top text-[12px] text-ink2">
                      {stamp(u.password_changed_at)}
                    </td>
                    <td className="border-b border-line px-2.5 py-2.5 align-top">
                      {u.must_change_password ? (
                        <span className="pill st" style={{ color: 'var(--high)' }}>must change</span>
                      ) : !u.is_active ? (
                        <span className="pill st">disabled</span>
                      ) : (
                        <span className="pill st st-resolved">ok</span>
                      )}
                    </td>
                    <td className="border-b border-line px-2.5 py-2.5 align-top">
                      {u.id === user.id ? (
                        <span className="text-[12px] text-ink3">you</span>
                      ) : (
                        <button
                          type="button" className="btn btn-ghost"
                          disabled={resetting !== null}
                          onClick={() => reset(u.id)}
                        >
                          {resetting === u.id ? 'Resetting…' : 'Reset'}
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {generated && (
            <div className="banner banner-warn mt-3.5" role="status">
              <strong>New password for {generated.username}:</strong>{' '}
              <span className="select-all font-mono text-[.92em]">{generated.password}</span>
              <br />
              <span className="text-[12px]">
                Shown once. Hand it over through a channel you trust — it is not stored
                anywhere in readable form and cannot be shown again.
              </span>
              <div className="mt-2.5">
                {/* The Jinja page loses this value on the next navigation. A SPA
                    would keep it on screen behind whatever the admin does next,
                    so "shown once" needs a way to end the showing. */}
                <button type="button" className="btn btn-ghost"
                        onClick={() => setGenerated(null)}>
                  I have handed it over
                </button>
              </div>
            </div>
          )}
        </>
      )}
    </>
  )
}
