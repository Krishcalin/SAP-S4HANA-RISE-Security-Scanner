import {
  Calculator, CircleAlert, ListOrdered, ScrollText, CircleDollarSign, Landmark, LayoutDashboard, LayoutGrid, Scissors, ShieldCheck, TrendingUp, Upload, UserCog, Waypoints, type LucideIcon,
} from 'lucide-react'
import type { Role } from '../api/types'

/**
 * The console's navigation, as data.
 *
 * A ROUTE WITH NO NAV ENTRY IS A ROUTE NOBODY FINDS. The sibling product shipped
 * its two-factor enrolment screen reachable only by typing the URL, which made
 * the whole feature look unwired for a release. Anything added to App.tsx that a
 * person is meant to reach on purpose belongs in this file too.
 *
 * The three DETAIL screens are the deliberate exceptions, and they are not
 * exceptions to the rule so much as instances of it: /findings/:id, /paths/:id
 * and /runs/:id take an id, so there is no single URL to put in a menu. They are
 * reached by clicking a row on the list screen above them, and a list screen that
 * does not link its rows strands them exactly as an unlisted route would.
 *
 * Saved views (/v/:slug) are the fourth: parameterised, and enumerated at runtime
 * rather than at build time. Sidebar.tsx fetches them and renders one link each.
 */
export interface NavItem {
  to: string
  label: string
  icon: LucideIcon
  /** Minimum role. Mirrors the server's own gate — the API refuses regardless,
   *  so this only decides whether a person is shown a door they cannot open. */
  minRole?: Role
}

export const NAV_MAIN: NavItem[] = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/findings', label: 'Findings', icon: CircleAlert },
  { to: '/trend', label: 'Trend', icon: TrendingUp },
  { to: '/paths', label: 'Risk Paths', icon: Waypoints },
  // Directly under the paths it cuts. The shortest worklist the product makes:
  // one fix, one or more paths gone.
  { to: '/chokepoints', label: 'Choke Points', icon: Scissors },
  // The currency figure. Neither incumbent produces one at all, which is why it
  // sits in the main list rather than under a reports submenu.
  { to: '/risk', label: 'Risk ($)', icon: CircleDollarSign },
  { to: '/coverage', label: 'Coverage', icon: ShieldCheck },
  { to: '/domains', label: 'Domains', icon: LayoutGrid },
  // Directly under Domains, because it is the same twelve buckets asked a
  // narrower question: not "how much is in each" but "what is worst in
  // each". The findings list cannot answer it — its first five rows can
  // all sit in one domain.
  { to: '/top-risks', label: 'Top5Risk', icon: ListOrdered },
  { to: '/crq', label: 'Quantify Risk', icon: Calculator },
  // Every framework this product maps. NIST CSF keeps its own entry below
  // because it has its own module and a Function-level screen; the other
  // nine had nowhere to appear until this existed.
  { to: '/compliance', label: 'Compliance', icon: ScrollText },
  { to: '/csf', label: 'NIST CSF', icon: Landmark },
  { to: '/upload', label: 'Upload', icon: Upload, minRole: 'analyst' },
]

export const NAV_ACCOUNT: NavItem[] = [
  { to: '/account', label: 'Account', icon: UserCog },
]

const RANK: Record<Role, number> = { viewer: 0, analyst: 1, admin: 2 }

/** Same rank comparison as server/auth.py `has_role`: a route requiring
 *  'analyst' also admits 'admin'. Kept in the same shape so the two are
 *  comparable by eye when one of them changes. */
export function allowed(item: NavItem, role: Role): boolean {
  return item.minRole === undefined || RANK[role] >= RANK[item.minRole]
}
