import { BrowserRouter, Route, Routes } from 'react-router'
import AuthGate from './components/AuthGate'
import Login from './components/Login'
import { AppShell } from './components/AppShell'
import { Placeholder } from './routes/Placeholder'
import { Account } from './routes/Account'
import { SavedView } from './routes/SavedView'
import { RunDetail } from './routes/RunDetail'
import { Upload } from './routes/Upload'
import { Coverage } from './routes/Coverage'
import { PathDetail } from './routes/PathDetail'
import { Paths } from './routes/Paths'
import { Risk } from './routes/Risk'
import { Trend } from './routes/Trend'
import { Dashboard } from './routes/Dashboard'
import { Findings } from './routes/Findings'
import { FindingDetail } from './routes/FindingDetail'

/**
 * The route table.
 *
 * ADDING A SCREEN IS TWO EDITS, AND BOTH ARE REQUIRED:
 *   1. a <Route> inside the AuthGate/AppShell layout below, and
 *   2. an entry in src/lib/nav.ts (or, for a detail screen taking an id, a link
 *      from the list screen above it).
 * A route with no way to reach it is a route nobody finds — the sibling product
 * shipped a whole feature that way. The catch-all Placeholder is what keeps a
 * half-done migration honest: an unmigrated path says so rather than rendering
 * an empty frame that reads as "no data".
 *
 * BASENAME COMES FROM THE BUILD. `import.meta.env.BASE_URL` is vite.config.ts's
 * `base`, which the SPA is currently built for at /ui/ while the Jinja console
 * still owns the bare paths. Every route path below is written WITHOUT the
 * prefix, so when server/app.py's SPA_MOUNT_PATH and vite's `base` both become
 * "/" nothing in this file changes.
 *
 * AuthGate wraps the layout rather than each screen: it resolves the session
 * once and provides it to everything underneath, so no screen has to ask again
 * and none of them can forget to.
 */
export default function App() {
  return (
    <BrowserRouter basename={import.meta.env.BASE_URL}>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route element={<AuthGate><AppShell /></AuthGate>}>
          {/* Screens land here. Keep them alphabetical by path once there are
              more than a handful; four agents editing this list will otherwise
              conflict on every line. */}
          <Route path="/" element={<Dashboard />} />
          <Route path="/account" element={<Account />} />
          <Route path="/coverage" element={<Coverage />} />
          <Route path="/findings" element={<Findings />} />
          {/* /findings/:id takes an id, so it has no nav entry: it is reached by
              clicking a row on /findings, which links both the check id and the
              title of every row it renders. */}
          <Route path="/findings/:id" element={<FindingDetail />} />
          <Route path="/paths" element={<Paths />} />
          {/* /paths/:id takes an id, so it has no nav entry either: it is reached by
              clicking a row on /paths, which links every row it renders. */}
          <Route path="/paths/:id" element={<PathDetail />} />
          <Route path="/risk" element={<Risk />} />
          {/* /runs/:id takes an id, so it has no nav entry: it is reached from the
              dashboard's recent runs and from the receipt the upload screen shows. */}
          <Route path="/runs/:id" element={<RunDetail />} />
          <Route path="/trend" element={<Trend />} />
          <Route path="/upload" element={<Upload />} />
          <Route path="/v/:slug" element={<SavedView />} />
          <Route path="*" element={<Placeholder />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
