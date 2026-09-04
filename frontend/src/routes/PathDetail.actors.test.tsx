/**
 * Who holds the privileges an attack path depends on.
 *
 * The hops on this page name the CHECKS that evidence them and never the
 * accounts, so this section is the one thing on the screen the path templates
 * cannot produce. It comes from the attack graph — which, until this landed,
 * every scan wrote and nothing read.
 *
 * TWO THINGS ARE BEING PROTECTED HERE, and neither is the table.
 *
 * The wording. An edge records what the export says is GRANTED. It never
 * evidences that a route was taken, and `used` on an edge means only that the
 * account logged on in the exported window. A page that turned that into
 * "this user attacked you" would be inventing a claim out of a configuration
 * file, which is what the rest of this product refuses to do.
 *
 * The empty state. No accounts is two different situations: a path whose
 * objects the graph does not reach (no answer) and a path it reaches and finds
 * nobody on (an answer). Drawing them alike would turn "we did not look" into
 * "you are fine", which is the failure this whole product reports on.
 */
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const fetchPath = vi.fn()

vi.mock('../api/client', () => ({
  path: (...a: unknown[]) => fetchPath(...a),
  ApiError: class ApiError extends Error {
    status: number
    constructor(status: number, message: string) { super(message); this.status = status }
  },
}))
vi.mock('../lib/title', () => ({ useTitle: () => {} }))
vi.mock('react-router', async () => {
  const actual = await vi.importActual<typeof import('react-router')>('react-router')
  return { ...actual, useParams: () => ({ id: '1' }) }
})

import { PathDetail } from './PathDetail'

function view(actors: unknown) {
  return {
    path: {
      id: 1, template_id: 'SAPPATH-01', landscape_id: 1,
      severity: 'CRITICAL', detail: { name: 'A path', hops: [] },
      loss_model: null, scenario_ale: null,
    },
    findings: [],
    cut_ids: [],
    actors,
  }
}

async function draw(actors: unknown) {
  fetchPath.mockResolvedValue(view(actors))
  render(<MemoryRouter><PathDetail /></MemoryRouter>)
  await screen.findByText('Who holds these privileges')
}

const ONE_ACTOR = {
  actors: [{
    actor: 'JSMITH', actor_type: 'user', any_used: true,
    via: [{ object: 'SAP_ALL', object_type: 'profile',
            edge_type: 'holds_profile', provenance: 'used',
            check_id: 'USR-002' }],
  }],
  edges_available: 42, reachable_objects: 4, objects_on_path: 49,
}

beforeEach(() => { vi.clearAllMocks() })

describe('the accounts a path depends on', () => {
  it('names the account and the privilege that put it there', async () => {
    await draw(ONE_ACTOR)
    expect(screen.getByText('JSMITH')).toBeInTheDocument()
    expect(screen.getByText('SAP_ALL')).toBeInTheDocument()
    expect(screen.getByText(/holds profile/)).toBeInTheDocument()
  })

  it('says how much of the path the graph could speak to', async () => {
    // 4 of 49 is a very partial answer, and a reader who is not told that will
    // read five accounts as the whole population.
    await draw(ONE_ACTOR)
    expect(screen.getByText(/reaches 4 of the 49 objects/)).toBeInTheDocument()
  })

  it('describes the privilege as held, never as used', async () => {
    await draw(ONE_ACTOR)
    expect(screen.getByText(/never that this route was taken/)).toBeInTheDocument()
  })

  it('reports logon evidence as being about the account, not the path', async () => {
    await draw(ONE_ACTOR)
    expect(screen.getByText('signed in during the exported window'))
      .toBeInTheDocument()
    expect(screen.queryByText(/used this path|took this route|attacked/i))
      .toBeNull()
  })

  it('does not claim quiet where there is simply no logon export', async () => {
    await draw({ ...ONE_ACTOR,
                 actors: [{ ...ONE_ACTOR.actors[0], any_used: false,
                            via: [{ ...ONE_ACTOR.actors[0].via[0],
                                    provenance: 'configured' }] }] })
    expect(screen.getByText('no logon evidence either way')).toBeInTheDocument()
  })
})

describe('an empty answer and no answer are different', () => {
  it('says so when the graph reaches none of the path', async () => {
    await draw({ actors: [], edges_available: 42, reachable_objects: 0,
                 objects_on_path: 49 })
    expect(screen.getByText(/it is the absence of one/)).toBeInTheDocument()
  })

  it('says so when the landscape has no edges at all', async () => {
    await draw({ actors: [], edges_available: 0, reachable_objects: 0,
                 objects_on_path: 49 })
    expect(screen.getByText(/No relationships have been derived/))
      .toBeInTheDocument()
  })

  it('states a real negative when the graph did reach the path', async () => {
    await draw({ actors: [], edges_available: 42, reachable_objects: 6,
                 objects_on_path: 49 })
    expect(screen.getByText(/No account holds a privilege the graph connects/))
      .toBeInTheDocument()
  })
})

describe('an older server', () => {
  it('omits the section rather than drawing an empty one', async () => {
    fetchPath.mockResolvedValue(view(undefined))
    render(<MemoryRouter><PathDetail /></MemoryRouter>)
    await screen.findByText('All evidence')
    expect(screen.queryByText('Who holds these privileges')).toBeNull()
  })
})
