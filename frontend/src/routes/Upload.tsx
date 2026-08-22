import { useEffect, useRef, useState, type FormEvent } from 'react'
import { Link } from 'react-router'
import {
  ApiError, landscapes as fetchLandscapes, systems as fetchSystems, upload,
} from '../api/client'
import type { Landscape, SapSystem, UploadResult } from '../api/types'
import { useSession } from '../lib/session'
import { useTitle } from '../lib/title'
// Aliased: this module already exports a component called `Upload`.
import { Upload as UploadIcon } from 'lucide-react'

/**
 * Upload an export bundle and start a scan.
 *
 * Ported from server/templates/upload.html, which was a plain <form> posting to
 * /api/upload. That worked, and it navigated the browser to the endpoint's JSON —
 * so the analyst's reward for uploading was a raw object, and the `note` field
 * explaining that the bundle was a byte-identical re-upload was rendered as a
 * quoted string in a wall of braces. The form is unchanged here, field for field;
 * what changes is that the response is READ: the run id becomes a link to the
 * screen where the scan can be watched, and the duplicate note becomes the
 * sentence it always was.
 *
 * NOTHING IS INSTALLED AND NOTHING IS CONNECTED TO. That copy is not marketing —
 * it is the product's whole shape, and it is why the form takes files rather than
 * a hostname and a service user. It survives the port verbatim.
 *
 * THE FORM STAYS AFTER A SUCCESSFUL UPLOAD rather than redirecting to the run. A
 * bundle is usually several exports from several systems, and uploading the next
 * one is the likeliest next act; redirecting would also throw away the receipt
 * (the content hash, and whether this bundle had been seen before), which is the
 * only place either is ever shown.
 */

/** Human bytes. The count alone does not tell an analyst whether they picked the
 *  four exports or the whole directory, and a bundle is the one thing on this
 *  screen that can be wrong in a way the server cannot detect for them. */
function size(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  const units = ['KB', 'MB', 'GB']
  let n = bytes / 1024
  let i = 0
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i += 1 }
  return `${n < 10 ? n.toFixed(1) : Math.round(n)} ${units[i]}`
}

/** Branch on the status, never on the message text. Each of these is a distinct
 *  thing the operator has to do something different about. */
function describe(err: unknown): string {
  if (!(err instanceof ApiError)) {
    return 'The upload did not complete — the connection failed. If the server had ' +
           'already accepted the files, a run will be waiting on the dashboard; ' +
           'check there before uploading again.'
  }
  switch (err.status) {
    case 400: return err.message      // "no files uploaded", "unsafe path in archive: …"
    case 403: return 'Uploading requires the analyst role.'
    case 404: return 'That landscape no longer exists. Reload the page to pick another.'
    case 413: return `${err.message}. Split the bundle and upload it in parts — ` +
                     'each upload becomes its own run and the findings merge by fingerprint.'
    default:  return err.message
  }
}

export function Upload() {
  useTitle('Upload')
  const { user } = useSession()

  const [landscapes, setLandscapes] = useState<Landscape[] | null>(null)
  const [systems, setSystems] = useState<SapSystem[]>([])
  const [refError, setRefError] = useState<string | null>(null)

  const [landscapeId, setLandscapeId] = useState('')
  const [systemId, setSystemId] = useState('')
  const [sid, setSid] = useState('')
  const [client, setClient] = useState('')
  const [files, setFiles] = useState<File[]>([])

  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<UploadResult | null>(null)

  // The file input stays uncontrolled — a FileList cannot be assigned — so
  // clearing it after a successful upload needs the element itself. Without this
  // the previous bundle is still selected and the obvious next click re-uploads it.
  const fileInput = useRef<HTMLInputElement>(null)

  useEffect(() => {
    let stopped = false
    // Landscapes are NOT scoped (a landscape carries no findings of its own) while
    // systems are, so a scoped analyst gets every landscape and only their own
    // systems. Both are needed before the form means anything, so one failure
    // fails the pair rather than half-populating it.
    Promise.all([fetchLandscapes(), fetchSystems()])
      .then(([ls, ss]) => {
        if (stopped) return
        setLandscapes(ls)
        setSystems(ss)
        // Preselect only when there is no choice to make. Guessing between two
        // landscapes would file a scan against the wrong estate on a mis-click.
        if (ls.length === 1) setLandscapeId(String(ls[0].id))
      })
      .catch((err) => {
        if (!stopped) {
          setLandscapes([])
          setRefError(err instanceof ApiError
            ? err.message
            : 'Could not load landscapes and systems.')
        }
      })
    return () => { stopped = true }
  }, [])

  async function submit(event: FormEvent) {
    event.preventDefault()
    setBusy(true)
    setError(null)
    setResult(null)
    try {
      const res = await upload(files, Number(landscapeId), {
        systemId: systemId ? Number(systemId) : undefined,
        sid: sid.trim() || undefined,
        client: client.trim() || undefined,
      })
      setResult(res)
      setFiles([])
      if (fileInput.current) fileInput.current.value = ''
    } catch (err) {
      setError(describe(err))
    } finally {
      setBusy(false)
    }
  }

  // The nav entry is already role-gated and the API refuses a viewer outright, so
  // this is only reachable by typing the URL. Say why rather than rendering a form
  // whose submit button is guaranteed to 403.
  if (!user.can_write) {
    return (
      <div className="max-w-2xl">
        <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2 mb-1">
          <UploadIcon size={22} className="text-accent shrink-0" />
          Upload an Export Bundle
        </h1>
        <div className="banner banner-info">
          Uploading requires the analyst role. Your account can read the console
          and its findings, but not start a scan.
        </div>
      </div>
    )
  }

  const noLandscape = landscapes !== null && landscapes.length === 0
  const totalSize = files.reduce((n, f) => n + f.size, 0)

  return (
    <div>
      <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2 mb-1">
        <UploadIcon size={22} className="text-accent shrink-0" />
        Upload an Export Bundle
      </h1>
      <p className="mb-5 text-ink2">
        CSV/JSON exports, or a zip of them. Nothing is installed in your SAP system
        and no connection is made — the scan runs entirely against the files you
        supply.
      </p>

      <div className="banner banner-info">
        Re-uploading the same bundle is fine and is how the mitigation journey is
        tracked. An identical bundle is detected and noted, not rejected.
      </div>

      {refError && (
        <div className="banner banner-bad" role="alert">
          <strong>Could not load the form.</strong> {refError}
        </div>
      )}

      {noLandscape && !refError && (
        <div className="banner banner-warn">
          No landscape is configured. An admin must create one before anything can
          be uploaded — a run belongs to a landscape, and there is nothing to file
          this one under.
        </div>
      )}

      {/* ── the receipt ──────────────────────────────────────────────────────
          Shown where the upload happened rather than carried to the run screen:
          the content hash and the duplicate note come from the upload response
          alone, and /api/runs/{id} cannot reproduce either. */}
      {result && (
        <div className="banner banner-ok">
          <strong>Run #{result.run_id} started.</strong>{' '}
          {result.files} file{result.files === 1 ? '' : 's'} accepted.{' '}
          <Link className="text-accent hover:underline" to={`/runs/${result.run_id}`}>
            Watch it run
          </Link>
          .
          <div className="mt-1.5 font-mono text-[12px] break-all text-ink3">
            {result.content_sha}
          </div>
          {result.note && (
            <div className="mt-1.5 text-ink2">
              {result.note}
              {result.duplicate_of_run !== null && (
                <>
                  {' '}
                  <Link className="text-accent hover:underline"
                        to={`/runs/${result.duplicate_of_run}`}>
                    See run #{result.duplicate_of_run}
                  </Link>
                  .
                </>
              )}
            </div>
          )}
        </div>
      )}

      {error && <div className="banner banner-bad" role="alert">{error}</div>}

      <form className="max-w-[620px] rounded-lg border border-cardline bg-panel p-4"
            onSubmit={submit}>
        <label className="block text-[12px] text-ink3" htmlFor="landscape">Landscape</label>
        <select id="landscape" className="field mt-1 mb-3.5" required
                value={landscapeId} disabled={busy || landscapes === null}
                onChange={(e) => setLandscapeId(e.target.value)}>
          {landscapes === null ? (
            <option value="">Loading…</option>
          ) : landscapes.length === 0 ? (
            <option value="" disabled>
              No landscape configured — an admin must create one first
            </option>
          ) : (
            <>
              <option value="" disabled>Choose a landscape</option>
              {landscapes.map((l) => (
                <option key={l.id} value={l.id}>{l.name} ({l.deployment_mode})</option>
              ))}
            </>
          )}
        </select>

        <label className="block text-[12px] text-ink3" htmlFor="system">
          System (optional — leave blank to register later)
        </label>
        <select id="system" className="field mt-1 mb-3.5" value={systemId} disabled={busy}
                onChange={(e) => setSystemId(e.target.value)}>
          <option value="">Unassigned</option>
          {systems.map((s) => (
            <option key={s.id} value={s.id}>{s.label} — {s.tier}</option>
          ))}
        </select>

        <div className="mb-3.5 flex gap-2.5">
          <div className="flex-1">
            <label className="block text-[12px] text-ink3" htmlFor="sid">SID</label>
            <input id="sid" className="field mt-1" type="text" placeholder="PRD"
                   maxLength={8} value={sid} disabled={busy}
                   onChange={(e) => setSid(e.target.value)} />
          </div>
          <div className="flex-1">
            <label className="block text-[12px] text-ink3" htmlFor="client">Client</label>
            <input id="client" className="field mt-1" type="text" placeholder="100"
                   maxLength={3} value={client} disabled={busy}
                   onChange={(e) => setClient(e.target.value)} />
          </div>
        </div>
        <p className="mb-3.5 text-[12px] text-ink3">
          SID and client identify the findings. Without them, uploads from two
          systems are indistinguishable and a landscape view is impossible.
        </p>

        <label className="block text-[12px] text-ink3" htmlFor="files">Files</label>
        {/* The dashed edge is inline rather than `border-dashed`: `.field` in
            src/index.css is unlayered CSS and beats every Tailwind utility, which
            all live in @layer utilities. */}
        <input id="files" ref={fileInput} className="field mt-1 mb-1 bg-panel2 p-2"
               style={{ borderStyle: 'dashed' }} type="file" multiple required
               disabled={busy}
               onChange={(e) => setFiles(Array.from(e.target.files ?? []))} />
        <p className="mb-4 text-[12px] text-ink3">
          {files.length > 0
            ? `${files.length} file${files.length === 1 ? '' : 's'} selected · ${size(totalSize)}`
            : 'A zip is expanded on the server; its contents are read, the archive is not kept.'}
        </p>

        <button type="submit" className="btn"
                disabled={busy || noLandscape || landscapes === null}>
          {busy ? 'Uploading…' : 'Upload and scan'}
        </button>
        {busy && (
          <p className="mt-2 text-[12px] text-ink3">
            The files are being transferred. The scan itself starts once they are
            stored and runs in the background, so this does not wait for it.
          </p>
        )}
      </form>
    </div>
  )
}
