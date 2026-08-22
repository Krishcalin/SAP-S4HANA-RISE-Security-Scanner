import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { afterEach, expect } from 'vitest'

/** React Testing Library mounts into a shared document; without this, one test's
 *  screen is still on the page during the next one's queries. */
afterEach(cleanup)

/**
 * THE ASSERTION THIS CONSOLE NEEDS MOST, available to every test.
 *
 * The product's rule is that "we could not look" must never render as "we looked
 * and found nothing". Every regression in that class has been a screen printing a
 * reassuring sentence over an absence of evidence, so the sentences themselves
 * are the thing to assert against — not a state name, which is what the code
 * under test already believes.
 *
 * Deliberately matched case-insensitively and against the WORDS a reader sees,
 * because the defect is always in what was rendered rather than in what the
 * component thought it was rendering.
 */
expect.extend({
  toMakeNoCleanClaim(received: HTMLElement) {
    const text = (received.textContent || '').toLowerCase()
    const claims = [
      'no findings',
      'nothing found',
      'assessed, and',
      'all clear',
      'fully assessed',
      '100%',
    ]
    const found = claims.filter((c) => text.includes(c))
    return {
      pass: found.length === 0,
      message: () =>
        found.length === 0
          ? 'expected a clean claim, and the screen made none'
          : `the screen claims cleanliness over an absence of evidence: `
            + `${found.map((f) => JSON.stringify(f)).join(', ')}`,
    }
  },
})

/* The generic parameter must match vitest's own `Assertion<T = any>` exactly —
   TypeScript refuses to merge two declarations of one interface whose type
   parameters differ, and `tsc --noEmit` catches it even though the tests run
   fine. That split is worth naming: `npm test` passing while `npm run build`
   fails is precisely the state this runner exists to stop shipping. */
declare module 'vitest' {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  interface Assertion<T = any> {
    /** Fails if the rendered output tells the reader anything is clean. Use on a
     *  screen rendered from a fixture where nothing was assessed. */
    toMakeNoCleanClaim(): T
  }
  interface AsymmetricMatchersContaining {
    toMakeNoCleanClaim(): unknown
  }
}
