import { Link, useLocation } from 'react-router'
import { useTitle } from '../lib/title'
import { SearchX } from 'lucide-react'

/**
 * The catch-all. The only file in routes/ that belongs to the shell.
 *
 * IT USED TO SAY SOMETHING ELSE, AND THAT MATTERED. While the migration was
 * running this screen was `Placeholder`: it read "not migrated yet" and offered a
 * button to `href={pathname}` — the same URL, served by the Jinja console, which
 * was the working version of whatever had landed here. That distinction was worth
 * a whole screen, because "nothing found" and "not built yet" are answers a
 * reviewer has to tell apart at a glance and an empty frame says neither.
 *
 * There is no server-rendered console any more, so that button now points at the
 * URL that just produced this screen: pressing it would reload and land here
 * again, a loop dressed as a way out. Every screen is migrated, so the only thing
 * that reaches this route is an address that does not name one — a typo, a link
 * to a screen that was renamed, or a stale bookmark from before the cutover. It
 * says exactly that, and sends the reader somewhere that exists.
 *
 * KEEP THE ROUTE. tests/test_spa_mount.py asserts App.tsx declares `path="*"`,
 * because without it an address with no route renders an empty layout that reads
 * as a screen with no data.
 */
export function NotFound() {
  useTitle('Page Not Found')
  const { pathname } = useLocation()
  return (
    <div className="max-w-xl">
      <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2 mb-1">
        <SearchX size={22} className="text-accent shrink-0" />
        Page Not Found
      </h1>
      <p className="text-ink2 text-[13px] mb-4">
        <code className="font-mono text-ink">{pathname}</code> is not a screen in
        this console. If you followed a link from before the console moved to this
        address, the same path without the <code className="font-mono text-ink">/ui</code>{' '}
        prefix is the one you want — and the server redirects it for you.
      </p>
      <Link className="btn inline-block no-underline" to="/">
        Back to the dashboard
      </Link>
    </div>
  )
}
