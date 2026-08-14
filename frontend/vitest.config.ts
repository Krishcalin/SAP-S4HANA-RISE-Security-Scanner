/*
 * Copyright (c) 2026 Krishnendu De. All Rights Reserved.
 *
 * Author : Krishnendu De
 * Coding Assistance : Claude Code
 * Code Security Assistance : Code QL
 */

import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

/**
 * The console's test runner.
 *
 * WHY THIS FILE EXISTS, AND WHAT IT COST TO NOT HAVE IT
 * The console reached ~5,000 lines of TSX with `tsc --noEmit` as its only check.
 * A type-checker proves the code COMPILES; it says nothing about what the screen
 * says. Two defects shipped through that gap in a single day:
 *
 *   * /csf/<fn> filed a `not_supplied` Category under "Assessed here" and told
 *     the reader "Assessed, and this run produced no findings against it" while
 *     showing the "Export not supplied" chip an inch above it;
 *   * the trend screen coerced a null pass rate to 0% with `?? 0`, so a category
 *     nobody had scanned rendered as the customer's worst-performing area and
 *     sorted to the top of the table.
 *
 * Both type-check perfectly. Both are the product's central discipline inverted
 * on screen. Neither could be caught by anything that existed.
 *
 * SEPARATE FROM vite.config.ts ON PURPOSE. That file is the production build and
 * carries the `base` that server/app.py's SPA_MOUNT_PATH must agree with; a test
 * config sharing it would put jsdom and a coverage provider in the path of the
 * artefact that ships. This one shares only the React plugin, which the tests
 * need in order to transform JSX and nothing more.
 *
 * NO NEW RUNTIME DEPENDENCY. vitest, jsdom and testing-library are devDependencies
 * of a build-time toolchain that already includes Vite and TypeScript. The
 * server's pinned runtime count stays at four, which is the charter.
 */
export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
    // The console talks to an API. A test that reaches a real one is a test that
    // fails for reasons unrelated to what it asserts, so the fetch boundary is
    // stubbed per file and never left to a live server.
    restoreMocks: true,
    clearMocks: true,
  },
})
