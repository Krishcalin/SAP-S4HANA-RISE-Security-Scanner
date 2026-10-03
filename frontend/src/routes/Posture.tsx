/*
 * Vulnerabilities and Mis-Configuration — the two posture lenses over findings.
 *
 * ONE SCREEN, TWO KINDS. Both answer "of everything we found, show me just the X",
 * where X is either a known flaw that needs a fix (missing SAP Security Notes +
 * exploitable custom code) or an insecure setting (parameters, policy, interfaces,
 * authorizations). The partition is server-side (server/finding_classes.py); this
 * renders whichever class the route asks for, grouped by subject.
 *
 * AN EMPTY GROUP IS NOT A CLEAN ONE. A class with nothing in it may mean the data
 * that feeds it was never supplied (no ABAP source, no SAP Notes export) — so the
 * empty states say "nothing found", never "you are safe".
 */
import { useEffect, useState } from 'react'
import { Link } from 'react-router'
import { ShieldAlert, SlidersHorizontal, type LucideIcon } from 'lucide-react'

import { ApiError, misconfiguration as fetchMisconfig, vulnerabilities as fetchVuln } from '../api/client'
import type { PostureGroup, PostureRow, PostureView } from '../api/types'
import { useTitle } from '../lib/title'
import { MeasuredWhen } from '../components/MeasuredWhen'

const CARD = 'rounded-lg border border-cardline bg-panel p-4'
const GRID = 'grid gap-3.5 [grid-template-columns:repeat(auto-fit,minmax(420px,1fr))]'
const LINK = 'text-accent hover:underline'
const _SEV = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

type Kind = 'vulnerability' | 'misconfiguration'

interface KindMeta {
  title: string
  icon: LucideIcon
  fetch: () => Promise<PostureView>
  noun: string
  intro: string
  banner: string
  groupEmpty: string
  failure: string
}

const META: Record<Kind, KindMeta> = {
  vulnerability: {
    title: 'Vulnerabilities',
    icon: ShieldAlert,
    fetch: fetchVuln,
    noun: 'vulnerability',
    intro: 'Known flaws that need a fix — missing SAP Security Notes (including '
      + 'actively-exploited notes) and exploitable weaknesses in custom code '
      + '(our ABAP scanner and imported SAP ATC / CVA results), grouped by source.',
    banner: 'No vulnerabilities found. To populate this, scan an estate that '
      + 'supplies a HotNews / Security Notes export and an abapGit code export — '
      + 'an empty list here is not a clean bill of health.',
    groupEmpty: 'Nothing found in this group. If the source that feeds it was not '
      + 'supplied, this is a blind spot, not a clean result.',
    failure: 'Could not load the vulnerabilities.',
  },
  misconfiguration: {
    title: 'Mis-Configuration',
    icon: SlidersHorizontal,
    fetch: fetchMisconfig,
    noun: 'misconfiguration',
    intro: 'Settings weaker than the SAP Security Baseline — profile parameters, '
      + 'password and logon policy, network and RFC exposure, cryptography, '
      + 'authorizations, database, cloud and more, grouped by subject.',
    banner: 'No misconfigurations found. If no configuration export was scanned, '
      + 'this is a blind spot, not a hardened system.',
    groupEmpty: 'Nothing below baseline in this subject.',
    failure: 'Could not load the misconfiguration findings.',
  },
}

function Counts({ counts }: { counts: Record<string, number> }) {
  const shown = _SEV.filter((s) => (counts[s] ?? 0) > 0)
  if (shown.length === 0) return null
  return (
    <div className="flex flex-wrap gap-1.5 shrink-0">
      {shown.map((s) => (
        <span key={s} className={`pill sev-${s}`}>{counts[s]} {s}</span>
      ))}
    </div>
  )
}

function Row({ f }: { f: PostureRow }) {
  return (
    <li className="flex items-start gap-2.5 py-2 border-b border-line last:border-0">
      <span className={`pill sev-${f.severity} shrink-0 mt-0.5`}>{f.severity}</span>
      <span className="shrink-0 mt-0.5 text-[11px] font-mono text-ink3 w-[22px]">
        {f.priority_tier ?? '—'}
      </span>
      <span className="min-w-0">
        <Link className={LINK} to={`/findings/${f.id}`}>{f.title}</Link>
        <span className="block text-[11px] text-ink3 font-mono truncate">
          {f.check_id}{f.sid ? <> · {f.sid}</> : null}
        </span>
      </span>
    </li>
  )
}

function GroupCard({ group, empty, noun }: { group: PostureGroup; empty: string; noun: string }) {
  return (
    <section className={CARD}>
      <div className="flex items-start justify-between gap-3 mb-1">
        <h2 className="text-[15px] font-semibold text-ink">{group.label}</h2>
        {group.total > 0 && <Counts counts={group.counts} />}
      </div>
      <p className="text-[12px] text-ink3 mb-2 max-w-prose">{group.blurb}</p>
      {group.findings.length === 0 ? (
        <p className="text-[13px] text-ink2 max-w-prose">{empty}</p>
      ) : (
        <>
          <ul className="mt-1">
            {group.findings.map((f) => <Row key={f.id} f={f} />)}
          </ul>
          <p className="mt-2.5 text-[12px] text-ink3">
            {group.total} {noun}{group.total === 1 ? '' : 's'} in this group.
          </p>
        </>
      )}
    </section>
  )
}

function Posture({ kind }: { kind: Kind }) {
  const meta = META[kind]
  useTitle(meta.title)
  const [view, setView] = useState<PostureView | null>(null)
  const [failure, setFailure] = useState<string | null>(null)

  useEffect(() => {
    let live = true
    setView(null)
    setFailure(null)
    meta.fetch()
      .then((data) => { if (live) setView(data) })
      .catch((problem) => {
        if (!live) return
        setFailure(problem instanceof ApiError ? problem.message : meta.failure)
      })
    return () => { live = false }
  }, [kind])   // eslint-disable-line react-hooks/exhaustive-deps

  if (failure) return <p className="text-crit">{failure}</p>
  if (!view) return <p className="text-ink2">Loading…</p>

  const Icon = meta.icon
  const nothing = view.totals.findings === 0

  return (
    <>
      <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2 mb-1">
        <Icon size={22} className="text-accent shrink-0" />
        {meta.title}
      </h1>
      <MeasuredWhen measured={view.measured} subject="scan" />
      <p className="text-ink2 mb-5 max-w-[80ch]">
        {meta.intro} {view.totals.findings} {meta.noun}
        {view.totals.findings === 1 ? '' : 's'} across {view.groups.length} groups.
      </p>

      {nothing && <div className="banner banner-info">{meta.banner}</div>}

      <div className={GRID}>
        {view.groups.map((g) => (
          <GroupCard key={g.id} group={g} empty={meta.groupEmpty} noun={meta.noun} />
        ))}
      </div>
    </>
  )
}

export function Vulnerabilities() { return <Posture kind="vulnerability" /> }
export function Misconfiguration() { return <Posture kind="misconfiguration" /> }
