import { useEffect, useState } from 'react'
import { NavLink } from 'react-router'
import { Bookmark } from 'lucide-react'
import { NAV_ACCOUNT, NAV_MAIN, allowed, type NavItem } from '../lib/nav'
import { views } from '../api/client'
import type { SavedView } from '../api/types'
import { useSession } from '../lib/session'

function Row({ item }: { item: NavItem }) {
  const Icon = item.icon
  return (
    <NavLink
      to={item.to}
      // `end` only on the root: without it "/" matches every path and the
      // dashboard entry stays highlighted on every screen.
      end={item.to === '/'}
      className={({ isActive }) =>
        `flex items-center gap-2.5 rounded-md px-3 py-2 text-[13px] font-medium transition-colors ${
          isActive ? 'bg-accentdim text-accent' : 'text-ink2 hover:bg-panel2 hover:text-ink'
        }`
      }
    >
      <Icon size={16} strokeWidth={2} />
      <span>{item.label}</span>
    </NavLink>
  )
}

/**
 * The console's one navigation surface.
 *
 * SAVED VIEWS ARE FETCHED, NOT DECLARED. A saved view is a durable URL per
 * audience — that is the product's answer to the incumbent's customers batch-
 * scripting PDF exports into SharePoint — and it only works if the views are
 * somewhere a person can click. They are parameterised (/v/:slug), so they
 * cannot live in the static nav table; this is where they get listed.
 *
 * A FAILED FETCH RENDERS NOTHING AND SAYS NOTHING. The saved-view list is
 * secondary chrome around the screen the user actually asked for, and an error
 * banner in the sidebar for it would be louder than the thing it interrupts.
 * The screens themselves report their own failures.
 */
export function Sidebar() {
  const { user } = useSession()
  const [saved, setSaved] = useState<SavedView[]>([])

  useEffect(() => {
    let cancelled = false
    views().then((v) => { if (!cancelled) setSaved(v) }).catch(() => { /* see above */ })
    return () => { cancelled = true }
  }, [])

  return (
    <aside className="w-56 shrink-0 border-r border-line bg-panel flex flex-col">
      <div className="h-[54px] flex items-center gap-2.5 px-4 border-b border-line">
        {/* The <source> selects the LIGHT mark and the <img> falls back to the
            dark one, which is the inverse of how it reads. It mirrors the
            stylesheet exactly: :root is the dark theme and only
            prefers-color-scheme: light overrides it, so a browser reporting
            "no-preference" gets the dark page and must get the mark that shows
            on it. base.html carries the same pair, written the same way. */}
        <picture>
          <source srcSet="/static/monitorrisk-mark.png" media="(prefers-color-scheme: light)" />
          <img src="/static/monitorrisk-mark-dark.png" alt="" width={22} height={22} />
        </picture>
        <span className="font-semibold tracking-tight text-ink">
          Monitor<span className="text-accent">Risk</span>
        </span>
      </div>

      <nav className="flex-1 overflow-y-auto py-3 px-2.5 flex flex-col gap-0.5">
        {NAV_MAIN.filter((i) => allowed(i, user.role)).map((i) => <Row key={i.to} item={i} />)}

        {saved.length > 0 && (
          <>
            <div className="mt-4 mb-1 px-3 text-[10px] font-semibold uppercase tracking-wider text-ink3">
              Saved Views
            </div>
            {saved.map((v) => (
              <NavLink
                key={v.slug}
                to={`/v/${v.slug}`}
                title={v.description ?? undefined}
                className={({ isActive }) =>
                  `flex items-center gap-2.5 rounded-md px-3 py-2 text-[13px] transition-colors ${
                    isActive ? 'bg-accentdim text-accent' : 'text-ink2 hover:bg-panel2 hover:text-ink'
                  }`
                }
              >
                <Bookmark size={16} strokeWidth={2} />
                <span className="truncate">{v.name}</span>
              </NavLink>
            ))}
          </>
        )}

        <div className="mt-4 mb-1 px-3 text-[10px] font-semibold uppercase tracking-wider text-ink3">
          You
        </div>
        {NAV_ACCOUNT.map((i) => <Row key={i.to} item={i} />)}
      </nav>

      {/* Row scope is stated, not implied. A user restricted to three systems is
          looking at a partial estate, and a console that renders it as the whole
          thing is lying by omission — "no critical findings" means something very
          different when two thirds of the landscape is invisible. */}
      {user.scoped_system_ids !== null && (
        <div className="px-4 py-3 border-t border-line text-[11px] text-ink3">
          Scoped to {user.scoped_system_ids.length} system
          {user.scoped_system_ids.length === 1 ? '' : 's'}
        </div>
      )}
    </aside>
  )
}
