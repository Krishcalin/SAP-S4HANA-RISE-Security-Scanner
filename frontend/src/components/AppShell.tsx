import { Outlet } from 'react-router'
import { Sidebar } from './Sidebar'
import { TopBar } from './TopBar'

/**
 * The frame every signed-in screen renders inside.
 *
 * The scroll lives on <main>, not on the document: the sidebar and the top bar
 * must stay put while a 500-row findings table moves. `min-w-0` on the column is
 * load-bearing — without it a wide table forces the flex child past the viewport
 * and the whole page scrolls sideways, taking the navigation off screen with it.
 */
export function AppShell() {
  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar />
      <div className="flex-1 flex flex-col min-w-0">
        <TopBar />
        <main className="flex-1 overflow-y-auto">
          <div className="mx-auto max-w-[1440px] px-6 py-6">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  )
}
