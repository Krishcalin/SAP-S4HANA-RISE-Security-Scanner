# The MonitorRisk console (React + TypeScript)

The console was 13 Jinja templates and is now this directory. It is compiled by
Vite at **build time** into `../server/spa/` and served as static files by the
**same FastAPI process** that serves the API — there is no Node at runtime, no
second container and no reverse proxy.

```
npm install
npm run dev          # http://localhost:5173, /api and /static proxied to :8000
npm run typecheck    # npx tsc --noEmit -p tsconfig.json
npm run build        # type-checks, then emits ../server/spa
```

`npm run build` is what the Dockerfile's first stage runs, so a type error fails
the image rather than shipping.

## Where the SPA lives

The bundle is built for and mounted at **`/`**. It sat at `/ui/` for the length
of the migration, because the Jinja console owned `/`, `/findings`, `/paths` and
every other bare path and those pages were the only working version of any screen
not yet ported — taking those URLs early would have stranded the product the
moment one was unfinished. Every screen landed on 2026-08-09, the templates and
their routes were deleted, and the console took the root. **Nothing in `src/`
changed**: route paths are written without a prefix and
`BrowserRouter basename={import.meta.env.BASE_URL}` supplies it.

Two constants have to agree and are asserted to, in `tests/test_spa_mount.py`:

| | |
|---|---|
| `base` in `vite.config.ts` | `'/'` — baked into every asset URL at build time |
| `SPA_MOUNT_PATH` in `server/app.py` | `'/'` |

A bundle built for one prefix and mounted at another is a blank page with four
404s in the console, so **re-run `npm run build` after changing either**. The
image always rebuilds; only a stale `../server/spa` on a developer's disk bites.

Three consequences of owning the root, all of them in `server/app.py`:

* **The mount is registered LAST.** A Mount at `/` matches every path and
  Starlette dispatches to the first match, so anything after it is dead code that
  answers 200 with `index.html`. `/api`, `/health` and `/static` are declared
  above it.
* **`/ui/*` answers 301** to the same path without the prefix, query string
  included. Those URLs were shared and bookmarked for the whole migration, and
  without the redirect they would resolve to the catch-all "page not found"
  screen instead of 404ing honestly.
* **An unmatched `/api` path 404s** rather than being answered with the console.
  `SpaFiles._index_or_404` refuses to fall back for anything under `api/`.

## Adding a screen

Two edits, and both are required.

**1. A route in `src/App.tsx`**, inside the `AuthGate`/`AppShell` layout, above
the catch-all:

```tsx
<Route path="/findings" element={<Findings />} />
<Route path="/findings/:id" element={<FindingDetail />} />
```

**2. A nav entry in `src/lib/nav.ts`** — or, for a screen that takes an id, a
link from the list screen above it:

```ts
{ to: '/findings', label: 'Findings', icon: CircleAlert },
{ to: '/upload', label: 'Upload', icon: Upload, minRole: 'analyst' },
```

A route with no way to reach it is a route nobody finds. A sibling product
shipped a whole feature reachable only by typing its URL, and it read as
completely unwired for a release. `nav.ts` already carries every top-level
destination; the parameterised screens (`/findings/:id`, `/paths/:id`,
`/runs/:id`, `/v/:slug`) cannot be in a static table and are reached by clicking
a row on the list screen above them — `/runs/:id` from the dashboard's recent
runs, `/v/:slug` from the saved-view list the sidebar fetches — which
means **a list screen that does not link its rows strands them exactly as an
unlisted route would**.

Screens live in `src/routes/`. `src/components/` and `src/lib/` belong to the
shell.

## Data

Everything goes through `src/api/client.ts`. It is the only place in the console
that calls `fetch` for data, one exported function per endpoint, all typed
against `src/api/types.ts` — which is transcribed from the SQL in `server/`, with
each interface naming the function it came from. If a shape looks wrong, open the
query it names rather than widening the type.

```tsx
import { findings, setFindingState, ApiError } from '../api/client'
import { useSession } from '../lib/session'

const { user } = useSession()          // the signed-in user, resolved by AuthGate
const page = await findings({ tier: 'P1', overdue: true })
```

Errors are `ApiError` and carry `.status`, so a screen can tell "you may not"
(403) from "it is not there" (404) from "the server broke" (5xx). Do not match on
message text.

**There is one mode and it talks to the API.** There is no sample/fixture mode
and there must not be one: this is an offline scanner whose entire value is that
the numbers came from the customer's own exports, and a console that can render
plausible findings from a fixture is a liability. A sibling product's fixture
mode is also how its authentication feature got tree-shaken out of a shipped
bundle. `tests/test_spa_mount.py` fails if `VITE_DATA_SOURCE`, `DATA_MODE` or a
`/sample/` fetch appears anywhere in `src/`.

**Writes are form-encoded, reads are JSON.** Not an inconsistency: the write
endpoints under `/api` take FastAPI `Form(...)` parameters because the Jinja
pages used to post to them directly. It is a published API that integrators call,
so the shape stayed when those pages went. `client.ts` handles it; screens should
not hand-roll a request. `/api/auth/*` and `/api/account/*` are the exception and
take JSON bodies — that is a CSRF control, not a style choice; see the header
of `server/api_auth.py`.

**Saving a view reads the REFERER, not a body.** `saveView()` saves what the
server can see you are looking at, so the filters must be in the address bar —
keep filter state in `useSearchParams`, not only in React state, or you will save
an empty view and the failure is silent.

## Styling

Tailwind v4, over the design tokens in `src/index.css`. Those tokens were copied
verbatim from the retired `server/templates/base.html`, which is why `sev-*`,
`st-*`, `own-*` and `tier-*` are the class names they are: a template's markup
ported across without re-deriving the palette, and the console looked like the
same product on the day it replaced the pages. `src/index.css` is now the only
definition of any of it.

Dark is `:root` and light is the `prefers-color-scheme` override — the inverse of
the usual convention, inherited from the same stylesheet. There is no theme
toggle; the console follows the OS, as the server-rendered pages always did.

## Dependency budget

react, react-dom, react-router, lucide-react, vite, typescript, tailwind. That is
the whole list. No state library, no component library, no data-fetching library,
no chart library. The product's discipline is a small dependency count and this
migration is not the excuse that ends it.
