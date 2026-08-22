import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router'
import { ApiError, checkDoc } from '../api/client'
import type { CheckDoc } from '../api/types'
import { useTitle } from '../lib/title'
import { RequirementRef } from '../components/Refs'
import { ScanSearch } from 'lucide-react'
import { CARD_TITLE as CARD_H3 } from '../lib/ui'

/**
 * What one check IS.
 *
 * The console could always tell you that LOG-AUD-001 fired. It could not tell
 * you what LOG-AUD-001 is: the id was dead text on the coverage screen and a
 * link to a FINDING everywhere else, so 709 published identifiers were explained
 * only in a markdown file no console reader can open.
 *
 * THIS PAGE IS PRODUCT FACTS, NOT ESTATE FACTS, and the split is deliberate.
 * Everything rendered here is true of the check itself, so it carries no row
 * scoping and needs none. The estate-specific half — where does this bite, for
 * me, right now — is a link into the findings queue, which is scoped once, in
 * the one place every other filter is scoped. A second query on this page would
 * be a second chance to get scoping wrong.
 *
 * UNDOCUMENTED IS SAID OUT LOUD. The knowledge base covers 357 of 709 ids. The
 * rest render everything else that is known — category, module, what that module
 * reads, the requirement it answers, the paths it evidences — above a plain
 * statement that no narrative is published yet. An empty panel would read as "we
 * have nothing", and a sentence assembled from the id would read as a
 * description while carrying no information.
 */

const CARD = 'rounded-lg border border-cardline bg-panel p-4'
const H2 = 'text-[15px] font-semibold text-ink mt-7 mb-2.5'
const LINK = 'text-accent hover:underline'
const G2 = 'grid gap-3.5 [grid-template-columns:repeat(auto-fit,minmax(340px,1fr))]'

/** Authored prose keeps its structure in newlines; HTML throws them away.
 *  Same rule as server/prose.py `paragraphs` and PathDetail: one paragraph per
 *  non-empty line, never a blank-line split. */
function paragraphs(text: string | null | undefined): string[] {
  if (!text) return []
  return text.split('\n').map((l) => l.trim()).filter((l) => l !== '')
}

export function CheckDetail() {
  const { id } = useParams()
  const [doc, setDoc] = useState<CheckDoc | null>(null)
  const [failure, setFailure] = useState<string | null>(null)

  useTitle(doc?.check_id ?? null)

  useEffect(() => {
    let live = true
    setDoc(null)
    setFailure(null)
    checkDoc(String(id))
      .then((d) => { if (live) setDoc(d) })
      .catch((e: unknown) => {
        if (!live) return
        const status = e instanceof ApiError ? e.status : 0
        setFailure(status === 404
          ? `No check with the id ${id}. It may be a typo, or an id retired from the catalogue.`
          : `This check could not be loaded${status ? ` (HTTP ${status})` : ''}.`)
      })
    return () => { live = false }
  }, [id])

  return (
    <>
      <p className="text-[12px] mb-2">
        <Link className={LINK} to="/coverage">&larr; Check catalogue</Link>
      </p>
      {failure && <div className="banner banner-bad">{failure}</div>}
      {!failure && doc === null && <p className="text-[13px] text-ink3">Loading…</p>}
      {doc !== null && <Body doc={doc} />}
    </>
  )
}

function Body({ doc }: { doc: CheckDoc }) {
  const cuts = doc.paths.filter((p) => p.is_cut)
  return (
    <>
      <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2 mb-1">
        <ScanSearch size={22} className="text-accent shrink-0" />
        <span className="font-mono">{doc.check_id}</span>
      </h1>
      <p className="text-ink2 mb-5">
        {doc.category ?? 'uncategorised'}
        {doc.module && <> · emitted by <span className="font-mono">{doc.module}</span></>}
      </p>

      {/* The single most actionable sentence this page can produce, so it goes
          above everything else rather than under a heading further down. */}
      {cuts.length > 0 && (
        <div className="banner banner-warn">
          <strong className="font-[650]">
            Closing this severs {cuts.length} risk path{cuts.length === 1 ? '' : 's'}.
          </strong>{' '}
          It is a cut on {cuts.map((p) => p.template_id).join(', ')} — not merely a
          contributing condition, but a step whose removal disconnects the route.
        </div>
      )}

      {doc.documented ? (
        <>
          <h2 className={H2}>What this check looks for, and why it matters</h2>
          <div className={CARD}>
            {paragraphs(doc.risk).map((para, i) => (
              <p key={i} className="mb-2.5 last:mb-0">{para}</p>
            ))}
          </div>

          <h2 className={H2}>How to remediate it</h2>
          <div className={CARD}>
            {paragraphs(doc.mitigation).map((para, i) => (
              <p key={i} className="mb-2.5 last:mb-0">{para}</p>
            ))}
          </div>
        </>
      ) : (
        /* Say it plainly. See the module docstring: an empty panel reads as "we
           have nothing to say", which is false — everything below is known. */
        <div className="banner banner-info">
          <strong className="font-[650]">
            No published description for this check yet.
          </strong>{' '}
          {doc.check_id} is a real check in the catalogue and runs like any other;
          what is missing is the written risk and remediation narrative, not the
          check. Everything below is derived from the code and from SAP&rsquo;s own
          catalogue, and is accurate regardless.
        </div>
      )}

      <h2 className={H2}>Where it comes from</h2>
      <div className={G2}>
        <div className={CARD}>
          <h3 className={CARD_H3}>Exports the module reads</h3>
          {doc.module_reads.length > 0 ? (
            <>
              <p className="text-[12px] text-ink2 -mt-1 mb-2.5">
                These are the exports <span className="font-mono">{doc.module}</span>{' '}
                reads in total. Which of them this single check touches is not
                derivable from the code, so this is the module&rsquo;s list, not a
                narrower claim about the check.
              </p>
              <p className="font-mono text-[12px] text-ink3 leading-relaxed">
                {doc.module_reads.join(' · ')}
              </p>
            </>
          ) : (
            <p className="text-[12px] text-ink2">
              The parser could not attribute this id to a module, so the exports
              behind it are not listed here rather than guessed.
            </p>
          )}
        </div>

        <div className={CARD}>
          <h3 className={CARD_H3}>SAP Baseline requirement</h3>
          {doc.requirements.length > 0 ? (
            <ul className="text-[13px] space-y-2">
              {doc.requirements.map((r) => (
                <li key={r.requirement}>
                  <RequirementRef id={r.requirement} />
                  {r.tier && <span className="text-ink3 text-[12px]"> · {r.tier}</span>}
                  {r.technology && (
                    <span className="text-ink3 text-[12px]"> · {r.technology}</span>
                  )}
                  {r.title && <div className="text-ink2 text-[12px]">{r.title}</div>}
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-[12px] text-ink2">
              This check answers no requirement in SAP&rsquo;s published Baseline. That
              is common and not a shortfall — most of what this product checks is
              beyond the Baseline, which covers a deliberately narrow set.
            </p>
          )}
        </div>
      </div>

      <h2 className={H2}>Risk paths this check appears on</h2>
      {doc.paths.length > 0 ? (
        <div className="rounded-lg border border-cardline bg-panel overflow-x-auto">
          <table className="w-full border-collapse">
            <thead>
              <tr>
                <th className="text-left text-[11px] font-semibold uppercase tracking-[.05em] text-ink3 px-2.5 py-2 border-b border-line w-[110px]">
                  Path
                </th>
                <th className="text-left text-[11px] font-semibold uppercase tracking-[.05em] text-ink3 px-2.5 py-2 border-b border-line">
                  Step it evidences
                </th>
                <th className="text-left text-[11px] font-semibold uppercase tracking-[.05em] text-ink3 px-2.5 py-2 border-b border-line w-[90px]">
                  Cut
                </th>
              </tr>
            </thead>
            <tbody>
              {doc.paths.map((p, i) => (
                <tr key={`${p.template_id}-${i}`} className="hover:bg-panel2">
                  <td className="px-2.5 py-2.5 border-b border-line align-top font-mono text-[12px]">
                    {p.template_id}
                  </td>
                  <td className="px-2.5 py-2.5 border-b border-line align-top text-[13px]">
                    {p.hop}
                    <div className="text-[12px] text-ink3">
                      {p.path_name}
                      {p.fair_scenario && (
                        <> · ends at <span className="font-mono">{p.fair_scenario}</span></>
                      )}
                    </div>
                  </td>
                  <td className="px-2.5 py-2.5 border-b border-line align-top">
                    {p.is_cut
                      ? <span className="pill sev-CRITICAL">cut</span>
                      : <span className="text-ink3 text-[12px]">—</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className={CARD}>
          <p className="text-[13px] text-ink2">
            This check evidences no step on any risk-path template. A short list
            of paths is the feature rather than a shortfall — most checks are not
            on one, and being absent here says nothing about the check&rsquo;s
            severity.
          </p>
        </div>
      )}

      <h2 className={H2}>In your estate</h2>
      <div className={CARD}>
        <p className="text-[13px] text-ink2 mb-2.5">
          Everything above is true of the check itself. What it has actually found
          here is a question about your estate, and the triage queue answers it
          with your scope applied.
        </p>
        <Link className={LINK}
              to={`/findings?check=${encodeURIComponent(doc.check_id)}`}>
          Open findings for {doc.check_id} &rarr;
        </Link>
      </div>
    </>
  )
}
