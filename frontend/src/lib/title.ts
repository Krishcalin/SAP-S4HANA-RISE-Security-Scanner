/*
 * Copyright (c) 2026 Krishnendu De. All Rights Reserved.
 *
 * Author : Krishnendu De
 * Coding Assistance : Claude Code
 * Code Security Assistance : Code QL
 */

import { useEffect } from 'react'

/**
 * The browser tab's name, per screen.
 *
 * WHY THIS EXISTS AT ALL. Every one of the thirteen Jinja templates declares a
 * `{% block title %}` — "Findings — MonitorRisk", "SAP-PRIV-03 — MonitorRisk",
 * "Run #418 — MonitorRisk". A SPA has ONE index.html and therefore one <title>,
 * so without this the whole console renders as thirteen identical tabs. That is
 * not cosmetic: the tab strip, the history menu and every bookmark someone takes
 * are all keyed on this string, and an analyst with the queue and two findings
 * open has no way to tell the three apart. It is exactly the kind of loss a
 * migration makes invisibly, because a screenshot of the page looks right.
 *
 * SET, NEVER RESTORED. An unmount handler putting the title back would fire
 * during the transition to the next screen, which sets its own title moments
 * later — the restore would win or lose depending on effect ordering, and a tab
 * that flickers back to the bare product name is worse than one that changes
 * once. The next screen is always responsible for the next title.
 *
 * A DETAIL SCREEN PASSES null WHILE IT LOADS. `null` leaves the previous title
 * alone rather than writing a placeholder, so navigating from the queue to a
 * finding does not blink through "— MonitorRisk" on the way.
 */
export function useTitle(title: string | null): void {
  useEffect(() => {
    if (title === null) return
    document.title = `${title} — MonitorRisk`
  }, [title])
}
