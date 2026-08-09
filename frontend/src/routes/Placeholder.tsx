import { useLocation } from 'react-router'
import { useTitle } from '../lib/title'

/**
 * The only file in routes/ that belongs to the shell. Everything else here is
 * owned by the screens being migrated — see the note in App.tsx.
 *
 * It exists so an unmigrated screen says so instead of rendering an empty frame
 * that looks like a screen with no data. The distinction matters during a phased
 * migration: "nothing found" and "not built yet" are answers a reviewer must be
 * able to tell apart at a glance, and the Jinja console is still serving the
 * working version of whatever landed here.
 */
export function Placeholder() {
  useTitle('Not migrated yet')
  const { pathname } = useLocation()
  return (
    <div className="max-w-xl">
      <h1 className="text-[21px] font-semibold tracking-tight text-ink mb-1">
        Not migrated yet
      </h1>
      <p className="text-ink2 text-[13px] mb-4">
        <code className="font-mono text-ink">{pathname}</code> has no React screen
        yet. The server-rendered console still serves this page while the
        migration is in progress.
      </p>
      <a className="btn inline-block no-underline" href={pathname}>
        Open the server-rendered version
      </a>
    </div>
  )
}
