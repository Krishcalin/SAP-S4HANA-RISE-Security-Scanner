# The MonitorRisk console (React + TypeScript)

The console is migrating from 13 Jinja templates to a React SPA. This directory
is the SPA. It is compiled by Vite at **build time** into `../server/spa/` and
served as static files by the **same FastAPI process** that serves the API —
there is no Node at runtime, no second container and no reverse proxy.

```
npm install
npm run dev          # http://localhost:5173, /api and /static proxied to :8000
npm run typecheck    # npx tsc --noEmit -p tsconfig.json
npm run build        # type-checks, then emits ../server/spa
```

`npm run build` is what the Dockerfile's first stage runs, so a type error fails
the image rather than shipping.

## Where the SPA lives, and why it is not at `/`

The bundle is built for and mounted at **`/ui/`**.

The Jinja console still owns `/`, `/findings`, `/paths` and every other bare
path, and those pages are the only working version of the screens that have not
been migrated yet. Taking those URLs before the screens exist would strand the
product the moment one of them was unfinished.

Two constants have to agree and are asserted to, in `tests/test_spa_mount.py`:

| | |
|---|---|
| `base` in `vite.config.ts` | `'/ui/'` — baked into every asset URL at build time |
| `SPA_MOUNT_PATH` in `server/app.py` | `'/ui'` |

When the last screen lands, both become `/`, the Jinja routes are deleted, and
**nothing in `src/` changes**: route paths are written without the prefix and
`BrowserRouter basename={import.meta.env.BASE_URL}` supplies it.

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
pages post to them directly, and those pages stay working for the whole
migration. `client.ts` handles it; screens should not hand-roll a request.

**Saving a view reads the REFERER, not a body.** `saveView()` saves what the
server can see you are looking at, so the filters must be in the address bar —
keep filter state in `useSearchParams`, not only in React state, or you will save
an empty view and the failure is silent.

## Styling

Tailwind v4, over the design tokens in `src/index.css`. Those tokens are copied
verbatim from `server/templates/base.html` so the two consoles look like one
product while both are running; `sev-*`, `st-*`, `own-*` and `tier-*` are the
same class names the templates use, so a template's markup ports across without
re-deriving the palette.

Dark is `:root` and light is the `prefers-color-scheme` override — the inverse of
the usual convention, matching `base.html`. There is no theme toggle; the console
follows the OS, as the Jinja pages always have.

## Dependency budget

react, react-dom, react-router, lucide-react, vite, typescript, tailwind. That is
the whole list. No state library, no component library, no data-fetching library,
no chart library. The product's discipline is a small dependency count and this
migration is not the excuse that ends it.
