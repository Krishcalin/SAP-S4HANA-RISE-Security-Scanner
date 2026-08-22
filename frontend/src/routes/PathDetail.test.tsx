import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { PathDetail, wrapWords } from './PathDetail'
import type { PathHop, PathView } from '../api/types'

/**
 * The per-path screen, and the mitigate-vs-additional split it exists to show.
 *
 * WHY THIS FILE EXISTS. `note` had been in the attack-path template schema since
 * SAPPATH-04 shipped, and it stopped dead at `instantiate()` in server/graph.py:
 * a template author could write the reason a step is not a cut and no reader
 * would ever see it. Nothing failed, because an unrendered field type-checks
 * exactly as well as a rendered one — the same shape of defect as the choke-point
 * table that the roadmap recorded as unbuilt while it was on screen.
 *
 * `why_cut` and `note` are the two halves of the same question and they are NOT
 * interchangeable. `why_cut` says what closing this step would achieve;
 * `note` most often says why closing it would achieve nothing, or why nobody
 * would agree to close it — "withdrawing emergency access is not a remediation
 * anyone will accept". A screen carrying only the first tells a reader to go and
 * do things that will be refused.
 */

vi.mock('../api/client', () => ({
  path: vi.fn(),
  ApiError: class ApiError extends Error {
    status: number
    constructor(status: number, message: string) {
      super(message)
      this.status = status
    }
  },
}))

vi.mock('../lib/title', () => ({ useTitle: () => {} }))

vi.mock('react-router', async () => {
  const actual = await vi.importActual<typeof import('react-router')>('react-router')
  return { ...actual, useParams: () => ({ id: '1' }) }
})

import { path as fetchPath } from '../api/client'

/** A hop built from api/types.ts rather than guessed, empty except what a test fills. */
function hop(over: Partial<PathHop> = {}): PathHop {
  return {
    name: 'Emergency access is granted and used',
    required: true,
    is_cut: false,
    why_cut: null,
    note: null,
    present: true,
    checks: ['GRC-FF-001'],
    finding_ids: [],
    evidence: [],
    evidence_total: 0,
    ...over,
  }
}

function view(hops: PathHop[], ale: number | null = null,
              applied = true): PathView {
  return {
    path: {
      id: 1,
      landscape_id: 1,
      template_id: 'SAPPATH-09',
      path_key: 'SAPPATH-09@1',
      entry_node: null,
      target_node: null,
      fair_scenario: 'SAP-PRIV-03',
      severity: 'HIGH',
      first_seen: '2026-08-22T00:00:00Z',
      last_seen: '2026-08-22T00:00:00Z',
      closed_at: null,
      closed_by_edge: null,
      ruleset_fingerprint: 'abc',
      scenario_ale: ale,
      loss_model: { applied },
      detail: {
        name: 'Emergency access without accountability',
        summary: 'A firefighter ID grants unrestricted privilege on demand.',
        narrative: 'Emergency access is a designed control, not a misconfiguration.',
        crosses_tier: false,
        system_ids: [1],
        hops,
        confidence: 'derived_from_config',
        confidence_note: 'Nothing was connected to, traversed or validated.',
      },
    },
    findings: [],
    cut_ids: [],
  }
}

function draw(hops: PathHop[], ale: number | null = null, applied = true) {
  vi.mocked(fetchPath).mockResolvedValue(view(hops, ale, applied))
  render(
    <MemoryRouter>
      <PathDetail />
    </MemoryRouter>,
  )
}

describe('PathDetail — the two halves of mitigate-vs-additional', () => {
  beforeEach(() => vi.clearAllMocks())

  it('renders a step note, so the reason a step is not a cut reaches the reader', async () => {
    draw([hop({
      note: 'Withdrawing emergency access is not a remediation anyone will accept.',
    })])
    await waitFor(() => {
      expect(screen.getByText(/not a remediation anyone will accept/)).toBeTruthy()
    })
  })

  it('renders why_cut and note together without either displacing the other', async () => {
    draw([hop({
      is_cut: true,
      why_cut: 'Restoring an independent controller severs the path.',
      note: 'The privilege itself is meant to be available.',
    })])
    await waitFor(() => {
      expect(screen.getByText(/Restoring an independent controller/)).toBeTruthy()
    })
    expect(screen.getByText(/meant to be available/)).toBeTruthy()
  })

  it('renders nothing extra when a hop carries no note', async () => {
    // The absence case. A guard that only ever checks the present case passes just
    // as happily against a component that renders the field unconditionally, which
    // would put an empty element under every step on every path.
    draw([hop({ note: null, why_cut: null })])
    await waitFor(() => {
      expect(screen.getByText(/Emergency access is granted and used/)).toBeTruthy()
    })
    expect(screen.queryByText(/not a remediation/)).toBeNull()
  })
})


/**
 * The label wrapper, which exists because the first one was wrong on screen.
 *
 * The shipped diagram sliced the step name at fixed character offsets --
 * `name.slice(0, 24)` then `name.slice(24, 46)` -- so it broke words wherever the
 * 24th character happened to land. Real output: "Unauthenticated entry po / int
 * exposed", and "OS command execution rea / chable". Anything past the 46th
 * character was dropped with nothing to say it had been.
 *
 * These are unit tests on a pure function rather than assertions about rendered
 * SVG, because the defect is in the string maths and that is where it can be
 * pinned precisely.
 */
describe('wrapWords', () => {
  it('never splits a word that fits on a line of its own', () => {
    // The exact label from the reported screenshot.
    const lines = wrapWords('Unauthenticated entry point exposed', 24, 3)
    expect(lines.join('|')).not.toMatch(/po\|int/)
    for (const line of lines) {
      expect(line.startsWith(' ')).toBe(false)
      expect(line.endsWith(' ')).toBe(false)
    }
    // Every word survives intact somewhere.
    const rejoined = lines.join(' ')
    for (const w of ['Unauthenticated', 'entry', 'point', 'exposed']) {
      expect(rejoined).toContain(w)
    }
  })

  it('keeps the second reported label whole too', () => {
    const lines = wrapWords('OS command execution reachable', 24, 3)
    expect(lines.join(' ')).toContain('reachable')
    expect(lines.join('|')).not.toMatch(/rea\|chable/)
  })

  it('respects the line budget and says when it truncated', () => {
    const lines = wrapWords(
      'A deliberately long step name that cannot possibly fit inside three short lines of text',
      24, 3)
    expect(lines.length).toBe(3)
    expect(lines[2].endsWith('\u2026')).toBe(true)
  })

  it('adds no ellipsis when nothing was dropped', () => {
    const lines = wrapWords('Short enough', 24, 3)
    expect(lines).toEqual(['Short enough'])
    expect(lines.join('').includes('\u2026')).toBe(false)
  })

  it('splits a word only when the word alone cannot fit', () => {
    // The one case where breaking a word beats overflowing the box.
    const lines = wrapWords('Supercalifragilisticexpialidocious', 12, 3)
    expect(lines[0].length).toBeLessThanOrEqual(12)
    expect(lines.length).toBeGreaterThan(0)
  })

  it('survives an empty label without throwing', () => {
    expect(wrapWords('', 24, 3)).toEqual([])
  })
})

describe('the route diagram', () => {
  beforeEach(() => vi.clearAllMocks())

  it('ends at a currency figure, not at the last condition', async () => {
    // The product's claim about itself: a path terminates in money rather than a
    // severity word. The diagram used to stop at the final hop, which quietly
    // contradicted it on the one screen where it is supposed to be visible.
    draw([hop({ name: 'Emergency access is granted and used' })], 4_200_000)
    await waitFor(() => {
      expect(screen.getByText('ENDS AT')).toBeTruthy()
    })
    // money() renders 4_200_000 as $4.20M: two fraction digits, and the
    // .00 strip only fires on whole millions.
    expect(screen.getAllByText(/\$4\.20M/).length).toBeGreaterThan(0)
  })

  it('says so when the scenario carries no figure', async () => {
    draw([hop({})], null)
    await waitFor(() => {
      expect(screen.getByText('no figures supplied')).toBeTruthy()
    })
  })

  it('exposes every step as a labelled, pressable control', async () => {
    // Keyboard and screen-reader access to a diagram that is otherwise pure
    // geometry. aria-pressed is also how selection is observable without
    // asserting on class names.
    draw([
      hop({ name: 'Emergency access is granted and used' }),
      hop({ name: 'Nobody independent reviews what it did', is_cut: true, present: true }),
    ])
    let steps: HTMLElement[] = []
    await waitFor(() => {
      steps = screen.getAllByRole('button', { name: /^Step \d+ of 2:/ })
      expect(steps.length).toBe(2)
    })
    expect(steps[1].getAttribute('aria-label')).toMatch(/This is a cut/)
    expect(steps[0].getAttribute('aria-pressed')).toBe('false')
  })

  it('selecting a step in the diagram marks it pressed', async () => {
    draw([hop({ name: 'Emergency access is granted and used' })])
    let step!: HTMLElement
    await waitFor(() => {
      step = screen.getByRole('button', { name: /^Step 1 of 1:/ })
    })
    expect(step.getAttribute('aria-pressed')).toBe('false')
    fireEvent.click(step)
    await waitFor(() => {
      expect(
        screen.getByRole('button', { name: /^Step 1 of 1:/ }).getAttribute('aria-pressed'),
      ).toBe('true')
    })
  })

  it('a step that is not present says so rather than showing a count', async () => {
    // The distinction the legend spells out: "not present" is not "less
    // important". A count of zero would read as the former being the latter.
    draw([hop({ present: false, evidence_total: 0 })])
    await waitFor(() => {
      expect(screen.getAllByText('not present').length).toBeGreaterThan(0)
    })
  })
})


/**
 * Which way the arrows point.
 *
 * THE DEFECT. The resize commit unified the entry connector with the
 * between-steps ones and computed its start as a constant, 26, while its end
 * stayed relative to the first box at `x - 11`. The first box sat at x = 30, so
 * the line ran from 26 to 19 -- right to left. `orient="auto"` faithfully turned
 * the arrowhead round to follow it, so the diagram pointed its entry arrow
 * BACKWARDS into its own start dot and drew it across the box it was meant to
 * point at.
 *
 * Nothing failed. Every existing test asserted what the boxes SAY; none asserted
 * where anything IS, and on a diagram whose entire subject is direction of
 * travel, a reversed arrow is a statement of the opposite of the truth.
 *
 * Geometry is testable in jsdom because it is plain SVG attributes -- one of the
 * quieter arguments for not reaching for a chart library.
 */
describe('the route diagram geometry', () => {
  beforeEach(() => vi.clearAllMocks())

  async function diagramLines(count: number) {
    draw(Array.from({ length: count }, (_, i) => hop({ name: `Step ${i + 1} name` })))
    let svg!: HTMLElement
    await waitFor(() => { svg = screen.getByRole('img', { name: 'Risk path diagram' }) })
    return Array.from(svg.querySelectorAll('line'))
  }

  it('every connector runs left to right, entry arrow included', async () => {
    // Three hops so the entry connector, a between-steps connector and the
    // terminus connector are all present in one render.
    const lines = await diagramLines(3)
    expect(lines.length).toBeGreaterThanOrEqual(4)
    for (const l of lines) {
      const x1 = Number(l.getAttribute('x1'))
      const x2 = Number(l.getAttribute('x2'))
      expect(Number.isFinite(x1) && Number.isFinite(x2)).toBe(true)
      expect(x2).toBeGreaterThan(x1)
    }
  })

  it('no connector starts inside the box it points at', async () => {
    // The other half of the same defect: the reversed line also overlapped the
    // first box. Every connector must finish before its target begins.
    const lines = await diagramLines(3)
    for (const l of lines) {
      expect(Number(l.getAttribute('x2')) - Number(l.getAttribute('x1')))
        .toBeGreaterThanOrEqual(12)
    }
  })

  it('the first connector clears the entry dot', async () => {
    const lines = await diagramLines(1)
    draw([hop({})])
    const svg = await screen.findByRole('img', { name: 'Risk path diagram' })
    const dot = svg.querySelector('circle')
    expect(dot).toBeTruthy()
    const edge = Number(dot!.getAttribute('cx')) + Number(dot!.getAttribute('r'))
    const first = Math.min(...lines.map((l) => Number(l.getAttribute('x1'))))
    expect(first).toBeGreaterThan(edge)
  })

  it('arrowheads do not scale with the stroke they sit on', async () => {
    // markerUnits defaults to "strokeWidth", which multiplies the marker by the
    // stroke. The resize took connectors from 1.5 to 3 and every arrowhead
    // silently doubled -- 9 units wide became 27, wide enough to cover the edge
    // of the box. A fixed head also keeps the live and still connectors wearing
    // the same arrow, which is what makes their weights comparable.
    draw([hop({})])
    const svg = await screen.findByRole('img', { name: 'Risk path diagram' })
    const markers = Array.from(svg.querySelectorAll('marker'))
    expect(markers.length).toBeGreaterThan(0)
    for (const m of markers) {
      expect(m.getAttribute('markerUnits')).toBe('userSpaceOnUse')
    }
  })
})


/**
 * The figure is the customer's, or it is not shown.
 *
 * `scenario_ale` is populated whether or not anyone told the model what an hour
 * of SAP downtime costs them — unpriced, it is the shipped catalogue's
 * illustrative $1bn manufacturer. The path payload carries `loss_model` for
 * exactly this reason; a null check on the number cannot tell the two apart,
 * and printing the second under a customer's name is the defect lib/pricing was
 * written to end.
 */
describe('the terminus and provenance', () => {
  beforeEach(() => vi.clearAllMocks())

  it('shows the figure when the customer priced it', async () => {
    draw([hop({})], 4_200_000, true)
    await waitFor(() => {
      expect(screen.getAllByText(/\$4\.20M/).length).toBeGreaterThan(0)
    })
  })

  it('withholds the figure when nobody priced it', async () => {
    // The same number, the same non-null scenario_ale. Only the provenance
    // differs, and it is the only thing that should decide this.
    draw([hop({})], 4_200_000, false)
    await waitFor(() => expect(screen.getByText('ENDS AT')).toBeTruthy())
    expect(screen.queryByText(/\$4\.20M/)).toBeNull()
    expect(screen.getByText('not quantified')).toBeTruthy()
  })

  it('keeps the exposure out of the header line too', async () => {
    // Two places print it. Gating one and not the other would leave the figure
    // on screen while the diagram claimed it was unavailable.
    draw([hop({})], 4_200_000, false)
    await waitFor(() => expect(screen.getByText('ENDS AT')).toBeTruthy())
    expect(screen.queryByText(/exposure/)).toBeNull()
  })
})
