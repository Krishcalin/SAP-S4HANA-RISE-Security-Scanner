import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// THE SPA IS A BUILD ARTEFACT OF THE ONE APP CONTAINER.
//
// `npm run build` emits static files into ../server/spa, which FastAPI serves
// from a StaticFiles mount next to the templates and brand assets it already
// serves. There is no Node process at runtime and no second container: React,
// Vite and TypeScript are build-time dependencies only, and the server's pinned
// runtime dependency count does not move.
//
// BASE AND THE SERVER MUST AGREE. `base` is baked into every asset URL at build
// time, so it cannot be an environment variable — a bundle built for '/ui/' and
// mounted at '/' loads nothing. server/app.py declares the same prefix as
// SPA_MOUNT_PATH, and tests/test_spa_mount.py asserts the two match so the pair
// can never be half-changed.
//
// WHY '/ui/' RATHER THAN '/'. The Jinja console still owns '/', '/findings',
// '/paths' and the rest while the screens are being migrated; registering the SPA
// over them would strand the product the moment a screen was unfinished. When the
// last screen lands, this string and SPA_MOUNT_PATH become '/' together and the
// Jinja routes go.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  base: '/ui/',
  build: {
    outDir: '../server/spa',
    emptyOutDir: true,
    // 'hidden' still WRITES the maps (so a crash can be symbolicated from the build
    // artefact) but omits the //# sourceMappingURL comment, so the browser does not
    // fetch them and they are not advertised. `true` published 1.76 MB of readable
    // TypeScript at /ui/assets/*.js.map to anyone who could reach the console —
    // including, before sign-in, anyone at all.
    sourcemap: 'hidden',
  },
  server: {
    port: 5173,
    // Dev only. The SPA runs on Vite and the API calls go to the FastAPI process
    // unchanged — NO path rewrite, because MonitorRisk's API genuinely lives at
    // /api rather than at the root. /static carries the brand assets the shell
    // renders, so it is proxied too or the logo is a broken image in dev.
    proxy: {
      '/api': { target: 'http://127.0.0.1:8000', changeOrigin: true },
      '/static': { target: 'http://127.0.0.1:8000', changeOrigin: true },
    },
  },
})
