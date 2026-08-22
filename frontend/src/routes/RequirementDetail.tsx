/*
 * Copyright (c) 2026 Krishnendu De. All Rights Reserved.
 *
 * Author : Krishnendu De
 * Coding Assistance : Claude Code
 * Code Security Assistance : Code QL
 */

import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router'
import { ApiError, requirementDoc } from '../api/client'
import type { RequirementDoc, Severity } from '../api/types'
import { useTitle } from '../lib/title'
import { CheckRefs } from '../components/Refs'
import { Landmark } from 'lucide-react'

/**
 * One SAP Baseline requirement family, and how this product answers it.
 *
 * The coverage table said "AUDIT-A · STANDARD · ABAP · Audit Log activated
 * (current values)" and stopped. A reader who wanted to know what AUDIT-A
 * actually requires — all of it, not the first of four titles — had nowhere to
 * go, which is an odd place for a product whose pitch is that it cites SAP's own
 * catalogue rather than inventing controls.
 *
 * SAP'S WORDING IS CARRIED VERBATIM AND LABELLED AS THEIRS. Every title here is
 * SAP's, not a paraphrase. The entire value of citing the Baseline is that the
 * words belong to the standard; rewording them would answer a question the
 * auditor did not ask, and would make the citation worth less than the sentence
 * it replaced.
 *
 * THE UNIT WARNING TRAVELS WITH THE NUMBER. `check_items` counts CHECK ITEMS in
 * the CSA policies, which is not the "control points" unit the Baseline document
 * counts — the widely-quoted 214 is that other unit and the two do not
 * reconcile. The coverage screen already carries that warning; a requirement page
 * printing a bare count without it would be the same claim, unqualified.
 */

const CARD = 'rounded-lg border border-line bg-panel p-4'
const CARD_H3 = 'text-[12px] font-semibold uppercase tracking-[.06em] text-ink3 mb-3'
const H2 = 'text-[15px] font-semibold text-ink mt-7 mb-2.5'
const LINK = 'text-accent hover:underline'
const G2 = 'grid gap-3.5 [grid-template-columns:repeat(auto-fit,minmax(340px,1fr))]'

/** SAP's tiers borrow the severity palette so the eye reads urgency the same way
 *  it does everywhere else. Transcribed from Coverage.tsx rather than invented,
 *  so the pill on this page matches the pill on the table that linked here. */
function tierSeverity(tier: string | null): Severity {
  if (tier === 'CRITICAL') return 'CRITICAL'
  if (tier === 'STANDARD') return 'HIGH'
  return tier ? 'LOW' : 'INFO'
}

export function RequirementDetail() {
  const { id } = useParams()
  const [doc, setDoc] = useState<RequirementDoc | null>(null)
  const [failure, setFailure] = useState<string | null>(null)

  useTitle(doc?.requirement ?? null)

  useEffect(() => {
    let live = true
    setDoc(null)
    setFailure(null)
    requirementDoc(String(id))
      .then((d) => { if (live) setDoc(d) })
      .catch((e: unknown) => {
        if (!live) return
        const status = e instanceof ApiError ? e.status : 0
        setFailure(status === 404
          ? `SAP publishes no Baseline requirement with the id ${id}.`
          : `This requirement could not be loaded${status ? ` (HTTP ${status})` : ''}.`)
      })
    return () => { live = false }
  }, [id])

  return (
    <>
      <p className="text-[12px] mb-2">
        <Link className={LINK} to="/coverage">&larr; Baseline coverage</Link>
      </p>
      {failure && <div className="banner banner-bad">{failure}</div>}
      {!failure && doc === null && <p className="text-[13px] text-ink3">Loading…</p>}
      {doc !== null && <Body doc={doc} />}
    </>
  )
}

function Body({ doc }: { doc: RequirementDoc }) {
  return (
    <>
      <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2 mb-1">
        <Landmark size={22} className="text-accent shrink-0" />
        <span className={`pill sev-${tierSeverity(doc.tier)}`}>
          {doc.tier || 'untiered'}
        </span>
        <span className="font-mono">{doc.requirement}</span>
      </h1>
      <p className="text-ink2 mb-5">
        SAP Security Baseline
        {doc.family && <> · family <span className="font-mono">{doc.family}</span></>}
        {doc.technology && <> · {doc.technology}</>}
      </p>

      {doc.covered ? (
        <div className="banner banner-ok">
          <strong className="font-[650]">This product answers {doc.requirement}.</strong>{' '}
          {doc.our_checks.length} check{doc.our_checks.length === 1 ? '' : 's'} map to
          it. Coverage is counted from the check ids actually in the catalogue, so
          this cannot drift from what the scanner really does.
        </div>
      ) : (
        <div className="banner banner-warn">
          <strong className="font-[650]">
            This product does not answer {doc.requirement}.
          </strong>{' '}
          It is published here so the gap is visible rather than absent — a
          coverage screen that listed only what it covers would be a marketing
          page, not an audit artefact.
        </div>
      )}

      <h2 className={H2}>What SAP requires</h2>
      <div className={CARD}>
        {/* SAP's wording, verbatim. See the module docstring. */}
        <p className="text-[12px] text-ink2 -mt-1 mb-2.5">
          SAP&rsquo;s own wording for every check item in this family, carried
          unchanged from the published CSA policies.
        </p>
        {doc.titles.length > 0 ? (
          <ul className="text-[13px] space-y-1.5 list-disc pl-5">
            {doc.titles.map((t, i) => <li key={i}>{t}</li>)}
          </ul>
        ) : (
          <p className="text-[13px] text-ink2">
            The catalogue carries no item titles for this requirement.
          </p>
        )}
      </div>

      <div className={`${G2} mt-3.5`}>
        <div className={CARD}>
          <h3 className={CARD_H3}>Configuration stores it reads</h3>
          {doc.config_stores.length > 0 ? (
            <p className="font-mono text-[12px] text-ink3 leading-relaxed">
              {doc.config_stores.join(' · ')}
            </p>
          ) : (
            <p className="text-[12px] text-ink2">None named in the catalogue.</p>
          )}
        </div>
        <div className={CARD}>
          <h3 className={CARD_H3}>SAP policies</h3>
          {doc.policies.length > 0 ? (
            <p className="font-mono text-[12px] text-ink3">{doc.policies.join(' · ')}</p>
          ) : (
            <p className="text-[12px] text-ink2">None named in the catalogue.</p>
          )}
          {doc.check_items !== null && (
            <p className="text-[12px] text-ink2 mt-2.5">
              {doc.check_items} check items.{' '}
              {/* The unit warning travels with the number, always. */}
              <span className="text-ink3">
                These are check items in the CSA policies, not the &ldquo;control
                points&rdquo; the Baseline document counts. The two units do not
                reconcile.
              </span>
            </p>
          )}
        </div>
      </div>

      <h2 className={H2}>How this product answers it</h2>
      <div className={CARD}>
        {doc.our_checks.length > 0 ? (
          <>
            <p className="text-[12px] text-ink2 -mt-1 mb-2.5">
              Every check that contributes to this requirement. Open one to read
              what it looks for and how to remediate it.
            </p>
            <p className="text-[13px] leading-loose">
              <CheckRefs ids={doc.our_checks} />
            </p>
          </>
        ) : (
          <p className="text-[13px] text-ink2">
            No check in the catalogue maps to this requirement.
          </p>
        )}
      </div>
    </>
  )
}
