import { createContext, useContext } from 'react'
import type { Me } from '../api/types'

/**
 * The signed-in user, resolved once by AuthGate and read by everything below it.
 *
 * WHY A CONTEXT AND NOT A STATE LIBRARY. There is exactly one piece of global
 * state in this console and it is written once per session. A store would be
 * three dependencies and a set of conventions to buy something React already
 * does; the product's discipline is a small dependency count and this is not the
 * place to spend it.
 *
 * WHY THE HOOK THROWS ON A MISSING PROVIDER rather than returning null: every
 * consumer sits inside AuthGate by construction, so a null here means the tree
 * was assembled wrongly. Returning null would push that mistake into each caller
 * as an optional-chaining habit, and the first one to forget it renders a blank
 * username instead of failing where the bug is.
 */
export interface Session {
  user: Me
  /** Re-read /api/auth/me. Call it after anything that changes the user's own
   *  record — a password change clears `must_change_password`, and a console
   *  still holding the old value keeps the account gated. */
  reload: () => Promise<void>
}

export const SessionContext = createContext<Session | null>(null)

export function useSession(): Session {
  const ctx = useContext(SessionContext)
  if (ctx === null) {
    throw new Error('useSession() used outside <AuthGate> — no session to read')
  }
  return ctx
}
