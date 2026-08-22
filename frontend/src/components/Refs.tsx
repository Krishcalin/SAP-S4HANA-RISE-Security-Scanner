/*
 * Copyright (c) 2026 Krishnendu De. All Rights Reserved.
 *
 * Author : Krishnendu De
 * Coding Assistance : Claude Code
 * Code Security Assistance : Code QL
 */

import { Link } from 'react-router'

/**
 * A check id and a Baseline requirement id, as links to what they mean.
 *
 * TWO KINDS OF CHECK ID APPEAR IN THIS CONSOLE and they are not
 * interchangeable. Getting them the same way round everywhere is the whole
 * reason these are components rather than inline `<Link>`s:
 *
 *   a FINDING      "LOG-AUD-001 fired here, on PRD/100"    -> /findings/{id}
 *   a REFERENCE    "AUDIT-A is answered by LOG-AUD-001"    -> /checks/LOG-AUD-001
 *
 * The first already had a link and keeps it: a reader clicking a row in the
 * triage queue wants THAT defect, not the definition behind it. Only the second
 * was dead text, and the coverage screen was the worst of it — a table whose
 * entire subject is which checks answer which requirement, rendering both as
 * plain grey monospace with nowhere to go.
 *
 * `CheckRef` therefore never replaces a finding link. Where a page shows a
 * finding, the definition is reachable from the finding's own page instead, once,
 * rather than from every row that mentions it.
 */

const REF = 'font-mono text-accent hover:underline'

export function CheckRef({ id, className = '' }: { id: string; className?: string }) {
  return (
    <Link className={`${REF} ${className}`} to={`/checks/${encodeURIComponent(id)}`}
          title={`What ${id} checks for`}>
      {id}
    </Link>
  )
}

export function RequirementRef({ id, className = '' }:
                               { id: string; className?: string }) {
  return (
    <Link className={`${REF} ${className}`}
          to={`/requirements/${encodeURIComponent(id)}`}
          title={`What SAP's ${id} requires`}>
      {id}
    </Link>
  )
}

/**
 * A list of check ids, separated and each its own link.
 *
 * `limit` renders a sample and says how many it kept back. The coverage screen
 * already did this with `.slice(0, 6)` and a `+N` suffix, for the stated reason
 * that a requirement family can map to thirty checks and the column is a sample
 * rather than an index — that behaviour is preserved here rather than quietly
 * dropped now that the ids have somewhere to go.
 */
export function CheckRefs({ ids, limit, separator = ' · ' }:
                          { ids: string[]; limit?: number; separator?: string }) {
  const shown = limit ? ids.slice(0, limit) : ids
  const held = ids.length - shown.length
  return (
    <>
      {shown.map((id, i) => (
        <span key={id}>
          {i > 0 && <span className="text-ink3">{separator}</span>}
          <CheckRef id={id} />
        </span>
      ))}
      {held > 0 && <span className="text-ink3"> +{held}</span>}
    </>
  )
}
