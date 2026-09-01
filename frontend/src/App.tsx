import { BrowserRouter, Route, Routes } from 'react-router'
import AuthGate from './components/AuthGate'
import Login from './components/Login'
import { AppShell } from './components/AppShell'
import { NotFound } from './routes/NotFound'
import { Account } from './routes/Account'
import { SavedView } from './routes/SavedView'
import { RunDetail } from './routes/RunDetail'
import { Upload } from './routes/Upload'
import { CheckDetail } from './routes/CheckDetail'
import { Chokepoints } from './routes/Chokepoints'
import { Coverage } from './routes/Coverage'
import { RequirementDetail } from './routes/RequirementDetail'
import { CrqInputs } from './routes/CrqInputs'
import { DomainDetail } from './routes/DomainDetail'
import { Domains } from './routes/Domains'
import { TopRisks } from './routes/TopRisks'
import { Csf } from './routes/Csf'
import { CsfFunction } from './routes/CsfFunction'
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
 * shipped a whole feature that way. The catch-all NotFound is what stops an
 * address with no route from rendering an empty frame that reads as "no data";
 * it said "not migrated yet" while there was a server-rendered console to fall
 * back to, and says what it now means instead.
 *
 * BASENAME COMES FROM THE BUILD. `import.meta.env.BASE_URL` is vite.config.ts's
 * `base`, now "/" — the console owns the root and the Jinja pages it was mounted
 * beside are deleted. Every route path below is written WITHOUT a prefix, which
 * is why the move from /ui/ changed nothing in this file: the paths here have
 * always been the ones people type, and only the basename in front of them moved.
 *
 * THESE PATHS ARE THE OLD CONSOLE'S PATHS, DELIBERATELY. /findings/123, /paths/7,
 * /runs/42 and /v/:slug are in bookmarks and in tickets, and each one is declared
 * below at the address it already had, so the cutover needed no redirect for any
 * of them. The one URL that did move — the /ui prefix itself — is redirected by
 * server/app.py rather than routed here, because a bundle cannot redirect a
 * request that never reaches it.
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
          <Route path="/checks/:id" element={<CheckDetail />} />
          <Route path="/chokepoints" element={<Chokepoints />} />
          <Route path="/requirements/:id" element={<RequirementDetail />} />
          <Route path="/crq" element={<CrqInputs />} />
          <Route path="/top-risks" element={<TopRisks />} />
          <Route path="/domains" element={<Domains />} />
          {/* /domains/:id takes a domain id, so it has no nav entry: it is
              reached from the twelve tiles on /domains. */}
          <Route path="/domains/:id" element={<DomainDetail />} />
          <Route path="/csf" element={<Csf />} />
          {/* /csf/:fn takes a Function id, so it has no nav entry: it is
              reached from the six Function tiles on /csf, and from the CSF
              strip on the dashboard. */}
          <Route path="/csf/:fn" element={<CsfFunction />} />
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
          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
