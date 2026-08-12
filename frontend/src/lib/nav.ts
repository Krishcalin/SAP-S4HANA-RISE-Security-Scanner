/*
 * Copyright (c) 2026 Krishnendu De. All Rights Reserved.
 *
 * Author : Krishnendu De
 * Coding Assistance : Claude Code
 * Code Security Assistance : Code QL
 */

import {
  Calculator,
  CircleAlert,
  CircleDollarSign,
  Landmark,
  LayoutDashboard,
  ShieldCheck,
  TrendingUp,
  Upload,
  UserCog,
  Waypoints,
  type LucideIcon,
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
  { to: '/paths', label: 'Attack paths', icon: Waypoints },
  // The currency figure. Neither incumbent produces one at all, which is why it
  // sits in the main list rather than under a reports submenu.
  { to: '/risk', label: 'Risk ($)', icon: CircleDollarSign },
  { to: '/coverage', label: 'Coverage', icon: ShieldCheck },
  { to: '/crq', label: 'Quantify risk', icon: Calculator },
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
