// The wire shapes, transcribed from server/ rather than guessed.
//
// WHERE EACH ONE COMES FROM is named in a comment above it, because that is the
// only thing that makes these verifiable: a hand-written type over a hand-written
// SQL SELECT is a claim about another file, and a claim nobody can check is a
// claim that rots. If you change one of these, open the query it names.
//
// TIMESTAMPS ARE STRINGS. psycopg hands FastAPI a datetime and FastAPI serialises
// it to an ISO-8601 string; nothing in the pipeline produces an epoch number.
// NUMERICS ARE NUMBERS BUT MAY BE null — a `numeric` column with no rows behind
// it aggregates to null, and "no data" is not "zero risk".

/** Severity vocabulary. Matches the check catalogue and the .sev-* CSS classes. */
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'

/** Lifecycle states — server/schema.sql `finding.state` CHECK constraint.
 *  `resolved` is set by the SCANNER not observing a finding again, never by a
 *  human clicking a button; see queries.ALLOWED_TRANSITIONS. */
export type FindingState =
  | 'open' | 'submitted_to_provider' | 'mitigated'
  | 'accepted' | 'false_positive' | 'resolved'

/** Who can actually act. In RISE a customer can SEE a bad profile parameter and
 *  cannot fix it, so this is the difference between an action and noise. */
export type RemediationOwner =
  | 'customer_fixable' | 'ticket_to_sap' | 'provider_owned' | 'not_assessable'

export type PriorityTier = 'P1' | 'P2' | 'P3' | 'P4'

export type Role = 'admin' | 'analyst' | 'viewer'

export type RunStatus =
  | 'pending' | 'parsing' | 'scanning' | 'deriving'
  | 'complete' | 'failed' | 'cancelled'

// Mirrors modules/deployment_modes.py DEPLOYMENT_MODES, which TypeScript cannot
// import; tests/test_deployment_modes.py asserts the two agree.
export type DeploymentMode = 'on_prem' | 'rise_pce' | 'rise_tailored' | 'rise_ecc'

// ── identity ────────────────────────────────────────────────────────────────
/** server/api_auth.py `user_payload` — an explicit allowlist, NOT the app_user
 *  row (which carries the password hash). */
export interface Me {
  id: number
  username: string
  display_name: string
  role: Role
  is_admin: boolean
  /** analyst or admin — gates the write affordances the API would refuse anyway. */
  can_write: boolean
  must_change_password: boolean
  last_login_at: string | null
  password_changed_at: string | null
  /** null means unrestricted; a list means the console is showing a SUBSET of the
   *  estate and should say so rather than implying it is the whole thing. */
  scoped_system_ids: number[] | null
  /** Present only on the sign-in response, never on /auth/me: whether this
   *  session was opened by spending a RECOVERY code rather than a live one. The
   *  console routes those people to the account screen, because they now have one
   *  fewer way back and an authenticator that is presumably gone. */
  used_recovery_code?: boolean
  /** How many single-use codes remain, or null when the account has no factor. */
  recovery_codes_left?: number | null
}

/** server/api_auth.py `api_account`. `users` is empty for a non-admin — the
 *  screen is still theirs, they just do not administer anyone. */
export interface AccountInfo {
  user: Me
  forced: boolean
  sessions: number
  users: AdminUser[]
}

export interface AdminUser {
  id: number
  username: string
  display_name: string | null
  role: Role
  is_active: boolean
  last_login_at: string | null
  /** null means the password has NEVER been chosen — the account is still on the
   *  one that was generated for it and printed to a terminal. Not the same
   *  question as `must_change_password`, which is cleared the moment somebody is
   *  let through. */
  password_changed_at: string | null
  must_change_password: boolean
}

/** The generated password from an admin reset. Shown ONCE and never persisted:
 *  it is in this response body and nowhere else, by design. */
export interface GeneratedPassword {
  username: string
  password: string
}

// ── reference data ──────────────────────────────────────────────────────────
/**
 * What kind of thing a system row is. Mirrors modules/platforms.py PLATFORMS,
 * which TypeScript cannot import; tests/test_platforms.py asserts they agree.
 */
export type Platform =
  | 'abap' | 'ariba' | 'btp' | 'cloud_alm'
  | 'concur' | 'fieldglass' | 'ias' | 'successfactors'

/**
 * server/queries.py `list_systems` — sap_system.* plus the landscape join.
 *
 * `sid` AND `client` ARE NULLABLE, AND WERE TYPED AS PLAIN `string`. A SaaS
 * tenant (decision D8) has neither, so under `strict: true` that declaration was
 * a compiler-enforced promise the backend can no longer keep. Prefer `label` for
 * anything a person reads: it is computed once in SQL and is correct for both
 * shapes, whereas `${sid}/${client}` renders "null/null" for a tenant and
 * `{sid && …}` silently renders nothing at all.
 */
export interface SapSystem {
  id: number
  landscape_id: number
  platform: Platform
  external_key: string | null
  /** "PRD/100" for ABAP, "successfactors:acme-sf-prod" for a tenant. */
  label: string
  sid: string | null
  client: string | null
  tier: 'prod' | 'qa' | 'dev' | 'sandbox' | 'unknown'
  product: string | null
  release: string | null
  kernel_patch: string | null
  btp_subaccount: string | null
  criticality: 'critical' | 'high' | 'medium' | 'low'
  exposure_zone: 'internet' | 'dmz' | 'internal' | 'isolated' | 'unknown'
  owner: string | null
  tags: string[]
  created_at: string
  landscape_name: string
  deployment_mode: DeploymentMode
}

/** server/queries.py `list_landscapes` — landscape.*. */
export interface Landscape {
  id: number
  name: string
  description: string | null
  deployment_mode: DeploymentMode
  rr_version: string | null
  created_at: string
}

// ── findings ────────────────────────────────────────────────────────────────
/** One row of server/queries.py `list_findings`: finding.* plus the check
 *  catalogue join and three derived columns. */
export interface FindingRow {
  id: number
  landscape_id: number
  system_id: number | null
  fingerprint: string
  check_id: string
  client: string | null
  /** How far to trust cross-run matching for THIS row. 'check_only' means the
   *  journey view is a coarse aggregate for it, and the dashboard counts these
   *  separately rather than pretending otherwise. */
  fingerprint_basis: 'objects' | 'display' | 'check_only'
  scope: 'object' | 'aggregate'
  subject: unknown[]
  severity: Severity | null
  priority_tier: PriorityTier | null
  priority_score: number | null
  /** The prioritiser's named factors — kept as data so a screen can show WHY a
   *  finding ranks where it does. Explainability is the product. */
  priority_factors: unknown[]
  priority_rationale: string | null
  state: FindingState
  remediation_owner: RemediationOwner
  assignee: string | null
  owning_team: string | null
  due_date: string | null
  provider_ticket_ref: string | null
  first_seen_run: number | null
  last_seen_run: number | null
  first_seen_at: string
  last_detected_at: string
  resolved_at: string | null
  /** open -> resolved -> open cycles. A finding that keeps coming back is a
   *  process failure, not a backlog item. */
  regression_count: number
  accepted_by: string | null
  acceptance_reason: string | null
  acceptance_from: string | null
  acceptance_due: string | null
  false_positive_reason: string | null
  transitioned_by: string | null
  last_transition_at: string | null
  sla_started_at: string | null
  taint_confidence: string | null
  reachability: string | null
  // ── from check_definition ──
  title: string
  category: string | null
  default_team: string | null
  baseline_req_id: string | null
  // ── from sap_system ──
  sid: string | null
  system_client: string | null
  system_tier: string | null
  platform: Platform | null
  external_key: string | null
  /** Computed in SQL (queries.SYSTEM_LABEL_SQL). Null when the run named no
   *  system at all — which is a real state, not an error. Use this rather than
   *  concatenating sid and client. */
  system_label: string | null
  // ── derived in SQL ──
  expired_acceptance: boolean
  is_overdue: boolean
  days_open: number
}

/** server/queries.py `list_findings` return value. */
export interface FindingPage {
  findings: FindingRow[]
  total: number
  page: number
  pages: number
}

/** server/queries.py `get_finding` — the row plus the authored knowledge base
 *  fields and the newest observation's details. */
export interface FindingDetail extends Omit<FindingRow,
  'default_team' | 'system_tier' | 'expired_acceptance' | 'is_overdue' | 'days_open'> {
  /** Authored prose: one paragraph per line, never blank-line separated. */
  risk_narrative: string | null
  /** Authored procedure: one numbered step per line. Render as a real list — see
   *  server/prose.py for why `white-space: pre-line` is not good enough. */
  remediation: string | null
  references_json: unknown[]
  responsibility: string | null
  cwe: string | null
  tier: string | null
  deployment_mode: DeploymentMode
  /** The newest observation's details — the code snippet and source→sink trace
   *  describe a PARTICULAR run, so they come from the observation, not the
   *  finding. */
  latest_details: Record<string, unknown> | null
  /** Whether the data behind the NEWEST observation was complete. Empty for a
   *  finding stored before the marker existed: not knowing is a third state,
   *  and rendering it as "complete" is what the marker exists to prevent. */
  latest_evidence: {
    complete?: boolean
    declared_sources?: number
    missing_sources?: string[]
  } | null
}

/** server/queries.py `finding_history` — finding_transition.*. */
export interface FindingTransition {
  id: number
  finding_id: number
  scan_run_id: number | null
  from_state: FindingState | null
  to_state: FindingState
  actor: string | null
  reason: string | null
  occurred_at: string
}

/** server/queries.py `finding_observations` — finding_observation.* + run start. */
export interface FindingObservation {
  id: number
  finding_id: number
  scan_run_id: number
  severity: Severity | null
  title: string | null
  description: string | null
  affected_items: unknown[]
  affected_objects: unknown[]
  affected_count: number
  details: Record<string, unknown>
  observed_at: string
  started_at: string
}

export interface FindingHistory {
  history: FindingTransition[]
  observations: FindingObservation[]
}

/** server/queries.py `transition_finding`. Note the keys are `from`/`to`. */
export interface TransitionResult {
  finding_id: number
  from: FindingState
  to: FindingState
}

/** server/queries.py `bulk_transition`. Deliberately NOT all-or-nothing: the
 *  moves that were legal are applied and the rest are reported with a reason. */
export interface BulkTransitionResult {
  applied: number[]
  applied_count: number
  skipped: { finding_id: number; reason: string }[]
  skipped_count: number
}

export interface AssignResult {
  finding_id: number
  changed: boolean
}

/** server/queries.py `changes_since` — the incremental-sync endpoint. */
export interface ChangesSince {
  since_run: number
  count: number
  findings: {
    id: number
    fingerprint: string
    check_id: string
    state: FindingState
    severity: Severity | null
    last_detected_at: string
    regression_count: number
    title: string
  }[]
}

// ── dashboard ───────────────────────────────────────────────────────────────
/** server/queries.py `dashboard_summary`. The three maps are sparse — a severity
 *  with no open findings is ABSENT, not zero. */
export interface DashboardSummary {
  by_severity: Partial<Record<Severity | 'UNKNOWN', number>>
  by_remediation_owner: Partial<Record<RemediationOwner, number>>
  by_state: Partial<Record<FindingState, number>>
  open_total: number
  /** An expired risk acceptance is itself an audit finding, which is why it is
   *  on the landing page rather than behind a filter nobody applies. */
  expired_acceptances: number
  weak_identity: number
  regressed: number
  /** How far the segregation-of-duties result can be believed, from SODCOV-000.
   *  Null when the ruleset-coverage module did not run — which is NOT the same
   *  as "usable", so the page renders nothing rather than a default. */
  sod_trust: {
    verdict: string
    limits: string[]
    severity: string
  } | null
}

/** server/app.py `api_dashboard`. */
export interface Dashboard {
  summary: DashboardSummary
  systems: SapSystem[]
  recent_runs: ScanRun[]
  crq: CrqPortfolio | null
  crq_scenarios: CrqScenario[]
}

// ── runs ────────────────────────────────────────────────────────────────────
/** server/queries.py `recent_runs` / `get_run` — scan_run.* plus joins.
 *  `landscape_name` and `deployment_mode` are present on get_run only. */
export interface ScanRun {
  id: number
  landscape_id: number
  system_id: number | null
  status: RunStatus
  content_sha: string | null
  uploaded_by: string | null
  upload_name: string | null
  started_at: string
  finished_at: string | null
  progress_done: number
  progress_total: number
  cancel_requested: boolean
  error: string | null
  /** Not cosmetic: a missing export file loads as None and its checks self-skip
   *  SILENTLY, so a partial upload otherwise produces a clean-looking report. */
  coverage: Record<string, unknown>
  module_status: Record<string, unknown>
  scanner_version: string | null
  sid: string | null
  client: string | null
  platform: Platform | null
  external_key: string | null
  /** Computed in SQL (queries.SYSTEM_LABEL_SQL). Null when the run named no
   *  system — scan_run LEFT JOINs sap_system, and an unattached upload is a real
   *  state (see the resolution guard in server/ingest.py), not an error. */
  system_label: string | null
  landscape_name?: string
  deployment_mode?: DeploymentMode
}

/** server/queries.py `run_diff`. */
export interface RunDiff {
  new: { id: number; check_id: string; severity: Severity | null; title: string }[]
  new_count: number
  persisting: number
  resolved: number
  regressed: {
    id: number; check_id: string; severity: Severity | null
    regression_count: number; title: string
  }[]
  regressed_count: number
  /** Findings this run left OPEN because no module that could have observed them
   *  ran. Not derivable from the finding rows — such a finding looks exactly
   *  like one that persisted — so it comes from what the run recorded.
   *
   *  NULL, NEVER 0, for a run stored before `scan_run.diff` existed: it did not
   *  withhold nothing, it did not measure. Draw no tile rather than a zero. */
  unexamined: number | null
  /** Set when the run carried no system, so nothing could be resolved at all. */
  resolution_skipped: string | null
}

/** server/app.py `api_upload`. `note` is non-null when the bundle is byte-identical
 *  to an earlier one — duplicate detection INFORMS, it does not block. */
export interface UploadResult {
  run_id: number
  files: number
  content_sha: string
  duplicate_of_run: number | null
  note: string | null
  status_url: string
}

// ── attack paths ────────────────────────────────────────────────────────────
// Called RISK PATHS in every word a reader sees. The wire shape, the table and
// the type keep `attack_path`: renaming those is a schema migration that moves
// every stored path's identity, and this was a change of articulation.
/** One hop of server/graph.py `_detail`. */
export interface PathHop {
  name: string
  required: boolean
  /** A CUT hop is one whose removal severs the path. A finding on a non-cut hop
   *  reduces exploitability without ending anything — the distinction is the
   *  whole value of the screen and must not be flattened in the UI. */
  is_cut: boolean
  why_cut: string | null
  note: string | null
  present: boolean
  checks: string[]
  finding_ids: number[]
  evidence: {
    id: number; check_id: string; severity: Severity | null
    sid: string | null; client: string | null; tier: string | null
  }[]
  evidence_total: number
}

/** server/graph.py `_detail` — the renderable shape stored in attack_path.detail. */
export interface PathDetail {
  name: string
  summary: string
  narrative: string
  crosses_tier: boolean
  system_ids: number[]
  hops: PathHop[]
  /** Stated on the path itself rather than left to the UI to remember. Nothing
   *  was connected to, traversed or validated — these conditions merely co-exist
   *  in the exported configuration. Render it. */
  confidence: string
  confidence_note: string
}

/** server/graph.py `list_paths` / `get_path` — attack_path.* plus the joins. */
export interface AttackPath {
  id: number
  landscape_id: number
  template_id: string
  path_key: string
  entry_node: number | null
  target_node: number | null
  fair_scenario: string | null
  severity: Severity | null
  first_seen: string
  last_seen: string
  closed_at: string | null
  closed_by_edge: number | null
  ruleset_fingerprint: string | null
  detail: PathDetail
  /** ale_p90 of the FAIR scenario this path ends at — the path ends at a
   *  currency figure, which is what no incumbent's report can produce. */
  scenario_ale: number | null
  /** Provenance of that figure, from the same crq_result row. Without it a path
   *  screen can only null-check the number, not ask whether it is the customer's
   *  own — which is the question lib/pricing exists to answer, and the reason
   *  the catalogue's illustrative $1bn manufacturer once printed under five
   *  customers' names. */
  loss_model?: { applied?: boolean } | null
  /** list_paths only. */
  finding_count?: number
}

/** server/graph.py `chokepoints` — the landing worklist, not the graph. Each row
 *  carries its consequence: "close this and N paths die". */
export interface Chokepoint {
  finding_id: number
  paths_cut: number
  scenarios: string[]
  check_id: string
  severity: Severity | null
  state: FindingState
  priority_tier: PriorityTier | null
  remediation_owner: RemediationOwner
  title: string
  sid: string | null
  client: string | null
}

/** server/app.py `api_chokepoints` — the worklist on its own screen.
 *
 *  Counts come from the rows returned, so they cannot disagree with the table
 *  under them. `open_paths` is the exception and comes from the path summary:
 *  summing `paths_cut` would count every path with more than one cut repeatedly,
 *  and most of them have more than one. */
export interface ChokepointsView {
  chokepoints: Chokepoint[]
  /** True when the query hit its cap. Returned rather than inferred: a list that
   *  stops at a round number looks identical to one that happened to end. */
  truncated: boolean
  summary: {
    total: number
    multi_path: number
    customer_fixable: number
    open_paths: number
  }
}

/** server/graph.py `path_summary`. `stale` counts paths derived under an older
 *  ruleset — say so rather than silently showing them as current. */
export interface PathSummary {
  open: number
  critical: number
  closed: number
  stale: number
}

/** server/app.py `api_paths`. */
export interface PathsOverview {
  summary: PathSummary
  paths: AttackPath[]
  chokepoints: Chokepoint[]
  closed: AttackPath[]
  template_count: number
}

/** server/graph.py `path_findings`. */
export interface PathFinding {
  id: number
  check_id: string
  severity: Severity | null
  state: FindingState
  priority_tier: PriorityTier | null
  remediation_owner: RemediationOwner
  title: string
  remediation: string | null
  sid: string | null
  client: string | null
}

/** server/app.py `api_path`. */
export interface PathView {
  path: AttackPath
  findings: PathFinding[]
  /** Findings sitting on a cut hop — the mitigate-vs-additional split. */
  cut_ids: number[]
}

// ── financial risk (FAIR) ───────────────────────────────────────────────────
/** server/crq.py `latest` — crq_result.* plus the run join. */
export interface CrqPortfolio {
  id: number
  scan_run_id: number
  scenario_id: string | null
  ale_p10: number | null
  ale_p50: number | null
  ale_p90: number | null
  ale_mean: number | null
  /** What the model did NOT price. Disclosing it is what separates this from
   *  vendor hand-waving, and a buyer with a risk function will test it. */
  unrouted_count: number
  /** FAIR runs on the UNFILTERED finding set, so a display filter can never move
   *  the currency figure. Recorded to prove it. */
  input_finding_count: number
  detail: Record<string, unknown>
  computed_at: string
  started_at: string
  run_id: number
  sid: string | null
  client: string | null
}

export type CrqScenario = Omit<CrqPortfolio, 'started_at' | 'run_id' | 'sid' | 'client'>

/** server/crq.py `trend` — oldest first (the query reverses a DESC LIMIT). */
export interface CrqTrendPoint {
  ale_p50: number | null
  ale_p90: number | null
  ale_mean: number | null
  unrouted_count: number
  run_id: number
  started_at: string
  input_finding_count?: number | null
  /** Digest of everything about the run that is NOT remediation — the model, the
   *  money assumptions, the coverage. The line may be drawn continuously ONLY
   *  between adjacent points whose fingerprints match; elsewhere it must break,
   *  because the two sides are not comparable. */
  inputs_fingerprint?: string
  /** P90 with every finding closed. It does not depend on the findings, so if it
   *  moves, something other than the customer's posture moved. */
  residual_p90?: number | null
}

/** server/app.py `api_risk`. */
export interface RiskView {
  portfolio: CrqPortfolio | null
  scenarios: CrqScenario[]
  trend: CrqTrendPoint[]
}

// ── the mitigation journey ──────────────────────────────────────────────────
/** server/analytics.py `sla_status`. The headline is CUSTOMER-fixable overdue
 *  work only: including provider-bound findings would report SAP's queue as the
 *  customer's breach. */
export interface SlaStatus {
  by_owner: Partial<Record<RemediationOwner, {
    remediation_owner: RemediationOwner
    overdue: number; due_soon: number; on_time: number; total: number
  }>>
  overdue_customer: number
  due_soon_customer: number
  overdue_provider: number
  total_tracked: number
}

/** server/analytics.py `aging_buckets` — one row per severity, the buckets as
 *  columns. Not one row per bucket: the SELECT uses count(*) FILTER. */
export interface AgingBucket {
  severity: Severity | null
  d0_7: number
  d7_30: number
  d30_90: number
  d90_plus: number
  total: number
  avg_days: number | null
}

/** server/analytics.py `mttr`. Computed over findings actually RESOLVED in the
 *  window — including still-open ones would make MTTR fall whenever a burst of
 *  new findings arrives, which is precisely backwards. */
export interface Mttr {
  window_days: number
  overall: { resolved: number; mean_days: number | null } | null
  by_severity: {
    severity: Severity | null; resolved: number
    mean_days: number | null; median_days: number | null
  }[]
  by_team: { team: string; resolved: number; mean_days: number | null }[]
  by_owner: {
    remediation_owner: RemediationOwner; resolved: number; mean_days: number | null
  }[]
}

/** server/analytics.py `burndown`, oldest first.
 *
 *  Per RUN rather than per calendar day, because the backlog only changes when a
 *  scan observes it — a daily series over weekly scans draws six flat days and a
 *  cliff, implying activity on days nothing was measured. Plot it as such. */
export interface BurndownPoint {
  run_id: number
  started_at: string
  new: number
  open_after: number
  critical: number
  p1: number
  p2: number
}

export interface BacklogTier {
  tier: string
  open: number
  overdue: number
  with_sap: number
  avg_age_days: number | null
}

export interface TechnicalDebt {
  stale_over_90d: number
  recurring: {
    id: number; check_id: string; severity: Severity | null
    regression_count: number; title: string; sid: string | null; client: string | null
  }[]
  expired_acceptances: {
    id: number; check_id: string; title: string
    accepted_by: string | null; acceptance_due: string | null
  }[]
}

/** server/analytics.py `team_scorecard`. `actionable` is the customer-fixable
 *  subset — the part of a team's queue they can actually act on today. */
export interface TeamScore {
  team: string
  open: number
  critical: number
  high: number
  overdue: number
  actionable: number
  avg_age_days: number | null
}

/** server/analytics.py `domain_scorecard`.
 *
 *  `pct_passing` is measured over CHECKS THAT ACTUALLY RAN, not the whole
 *  catalogue — scoring against every check ever written would let a customer
 *  improve their score by supplying fewer exports. Null when nothing ran.
 *
 *  IT IS A PASS RATE, NOT A COMPLIANCE SCORE, and the console must not present it
 *  as one. It was rendered under a column headed "Compliant" with a green/amber/
 *  red bar until it was noticed that the colour is severity-blind: sixteen passes
 *  and four CRITICAL failures is eighty per cent and was drawn green.
 *
 *  IT WAS CALLED `pct_compliant` UNTIL THE PRODUCT WAS CHECKED AGAINST ITS OWN
 *  PROMISE. The architecture guide states, twice and without qualification, that
 *  there is deliberately no compliance percentage anywhere in the product; this
 *  field was the one place that was not true. The note that used to sit here
 *  argued the rename was a breaking change not worth making for one word. It was
 *  neither: this console is the only consumer, it lives in the same repository,
 *  and the word was the entire point. A percentage labelled "compliant" is a
 *  claim about conformance with an external standard, which is precisely the
 *  claim `modules/compliance_mapping.py` refuses to make. */
export interface DomainScore {
  category: string | null
  /** How many checks EXIST in this category, read from the scanner's source —
   *  not how many have failed here. The old field counted the latter and called
   *  it the former, so a category where three of forty checks had ever produced
   *  a finding had a denominator of three. A floor: rule-table checks are built
   *  at runtime and are not literals, so they are not counted. */
  checks_known: number
  checks_failing: number
  /** Null, never 0, when nothing assessed this category. Zero is a measured
   *  result and this is the absence of one. */
  pct_passing: number | null
  /** False when no module feeding this category ran for the systems in scope. */
  assessed: boolean
}

/** server/analytics.py `journey_summary` — one call for the trend screen. */
export interface Journey {
  sla: SlaStatus
  aging: AgingBucket[]
  mttr: Mttr
  burndown: BurndownPoint[]
  backlog_by_tier: BacklogTier[]
  technical_debt: TechnicalDebt
  teams: TeamScore[]
  domains: DomainScore[]
}

// ── Baseline coverage ───────────────────────────────────────────────────────
/** server/sapcontent.py `coverage`, plus the catalogue metadata api_coverage adds.
 *
 *  THREE numbers rather than one percentage, deliberately: `beyond_baseline` is
 *  our checks that map to no SAP requirement, which is not a failure — SoD, GRC,
 *  financial controls and the attack-path content have no Baseline equivalent,
 *  and that is precisely where the product goes beyond it. */
export interface Coverage {
  baseline_version: string | null
  requirements_published: number
  /** Published minus the technologies this product does not scan. The ratio a
   *  reader should judge us on: comparing `requirements_covered` against
   *  `requirements_published` counts ten NetWeaver Java requirements as gaps,
   *  and no amount of work here would ever close them. */
  requirements_in_scope: number
  requirements_covered: number
  covered: {
    requirement: string; tier: string; technology: string
    title: string; our_checks: string[]
  }[]
  /** IN-SCOPE gaps only. `covered`, `not_covered` and `out_of_scope` partition
   *  the published set, so the three still add up and nothing was dropped. */
  not_covered: {
    requirement: string; tier: string; technology: string; title: string
  }[]
  /** Requirements for a stack this product does not read. Named with the reason
   *  rather than silently excluded — the denominator has to be honest in both
   *  directions, and hiding these would flatter the ratio exactly as counting
   *  them as gaps understates it. */
  out_of_scope: {
    requirement: string; tier: string; technology: string
    title: string; reason: string
  }[]
  beyond_baseline: string[]
  note: string
  meta: Record<string, unknown>
  /** Check ids written as literals in the scanner. A property of the
   *  PRODUCT: the same on every install, and it does not move when a
   *  customer's findings close. */
  our_checks: number
  /** How many of our checks have ever produced a finding in THIS tenant.
   *  A fact about the estate, not about the product — and the number this
   *  screen used to publish as though it were the second. */
  observed_checks: number
}

// ── saved views ─────────────────────────────────────────────────────────────
/** server/queries.py `save_view` / `list_views` — saved_view.*.
 *  A view stores FILTERS, never rows: opening it re-runs the query under the
 *  caller's own scope, so a shared link can never widen access. */
export interface SavedView {
  id: number
  slug: string
  name: string
  description: string | null
  kind: 'findings' | 'trend' | 'coverage'
  filters: Record<string, string>
  created_by: string | null
  is_shared: boolean
  created_at: string
  updated_at: string
}

/** server/app.py `api_view` — a resolved saved view. */
export interface ResolvedView {
  view: SavedView
  kind: SavedView['kind']
  filters: Record<string, string>
}

/** server/app.py `api_save_view`. */
export interface SaveViewResult {
  slug: string
  url: string
  filters: Record<string, string>
}

// ── operational ─────────────────────────────────────────────────────────────
/** server/app.py `health`. Degraded components are reported, never hidden — a
 *  green light over a broken collector is worse than a red one. */
export interface Health {
  status: 'ok' | 'degraded'
  degraded: string[]
}

/** The filter vocabulary the findings queue accepts. Mirrors the parameters of
 *  `queries.list_findings`; `queries.VIEW_FILTER_KEYS` is the allowlist a saved
 *  view may carry. */
export interface FindingFilters {
  system_id?: number | null
  state?: FindingState | null
  severity?: Severity | null
  team?: string | null
  owner?: RemediationOwner | null
  tier?: PriorityTier | null
  category?: string | null
  assignee?: string | null
  overdue?: boolean
  /** One of the twelve security domains, by id. The server refuses an unknown
   *  one and refuses the domain it does not assess, rather than answering the
   *  first with the whole queue and the second with an empty one. */
  domain?: string | null
  /** One check id. The server refuses an id the catalogue does not publish,
   *  rather than answering the narrowest possible question with the whole
   *  queue. This is what a check's own page links out to. */
  check?: string | null
  page?: number
}

// ── the check catalogue, and SAP's Baseline requirements ────────────────────
/** server/checkdocs.py `check` — what one check IS, assembled from the sources
 *  that are each already the authority for their own field. */
export interface CheckDoc {
  check_id: string
  category: string | null
  /** The module that emits it, or null for an id the parser cannot attribute. */
  module: string | null
  /** The exports that MODULE reads. Module-level and labelled as such on the
   *  screen: which of them a single check touches is not derivable, and a
   *  narrower list would be a claim the parser cannot support. */
  module_reads: string[]
  /** True when prose exists from ANY of the three sources below. False for the
   *  154 published ids none of them describes; the screen says so plainly rather
   *  than rendering an empty panel. */
  documented: boolean
  /** Which kind of answer the reader is getting. The three are NOT equivalent
   *  and the page says which it is showing:
   *    `knowledge_base`        a page written about this check
   *    `knowledge_base_family` a page written about the family it belongs to —
   *                            hand-written, but about sixteen patterns rather
   *                            than this one
   *    `rule_definition`       the two sentences the rule generating the check
   *                            already carried
   *  Counting them as one would overstate the written knowledge base by 198. */
  doc_source: 'knowledge_base' | 'knowledge_base_family' | 'rule_definition' | null
  /** The family id, or which rule corpus — whichever `doc_source` names. */
  doc_detail: string | null
  /** What THIS rule matches, when the narrative above it is about a family of
   *  them. A family narrative cannot say which of its patterns fired; this can,
   *  and it is never a substitute for the narrative. */
  doc_specific: string | null
  risk: string | null
  mitigation: string | null
  requirements: {
    requirement: string
    tier: string | null
    technology: string | null
    title: string | null
  }[]
  /** Risk-path steps this check evidences. `is_cut` is the most actionable
   *  thing this page can say: closing it severs a route. */
  paths: {
    template_id: string
    path_name: string | null
    severity: Severity | null
    fair_scenario: string | null
    hop: string | null
    is_cut: boolean
    required: boolean
  }[]
}

/** server/checkdocs.py `requirement` — one SAP Baseline requirement family. */
export interface RequirementDoc {
  requirement: string
  family: string | null
  technology: string | null
  tier: string | null
  /** SAP's own wording for every check item in the family, carried verbatim. */
  titles: string[]
  config_stores: string[]
  check_items: number | null
  policies: string[]
  our_checks: string[]
  covered: boolean
}

/** server/app.py `api_check_index`. */
export interface CheckIndexEntry {
  check_id: string
  category: string | null
  module: string | null
  documented: boolean
}

/** server/api_auth.py `api_totp_status`. */
export interface TotpStatus {
  enabled: boolean
  /** An enrolment started and never confirmed. It cannot satisfy a sign-in and
   *  expires after fifteen minutes — shown so a half-finished setup is visible
   *  rather than looking like "off". */
  pending: boolean
  confirmed_at: string | null
  recovery_codes_left: number
}

/** server/api_auth.py `api_totp_begin`. Nothing here is live yet. */
export interface TotpEnrolment {
  secret: string
  formatted_secret: string
  uri: string
  /** Inline SVG, or "" when the encoder could not produce one. The screen renders
   *  the key and the link regardless — the picture is a convenience and must
   *  never be the only way through enrolment. */
  qr_svg: string
}

/** server/api_auth.py `api_totp_confirm`. `recovery_codes` is the ONLY time these
 *  are ever readable: the server stores hashes. */
export interface TotpConfirmed {
  enabled: boolean
  recovery_codes: string[]
  other_sessions_revoked: boolean
}

// ── NIST CSF 2.0 ────────────────────────────────────────────────────────────

/** One of the six CSF Function ids. server/app.py `api_csf`. */
export type CsfFunctionId = 'GV' | 'ID' | 'PR' | 'DE' | 'RS' | 'RC'

/**
 * Whether this product can speak to a Category at all.
 * modules/nist_csf.py — ASSESSED / CLEAR / NOT_ASSESSED.
 *
 * FOUR states, and no two of them may render alike. `not_assessed` is a property
 * of the PRODUCT — no SAP export can answer this outcome, on any run.
 * `not_supplied` is a property of THIS run — the Category is assessable and
 * nothing that feeds it executed. `clear` is the only one that means we looked.
 *
 * `clear` and `not_assessed` are NOT interchangeable and must not render alike:
 * clear means the run produced no findings, not_assessed means no SAP export
 * answers that outcome in any run.
 */
export type CsfStatus = 'assessed' | 'clear' | 'not_supplied' | 'not_assessed'

/** A CSF Subcategory: NIST's id and its outcome text, verbatim. */
export interface CsfSubcategory {
  id: string
  text: string
}

/** A CSF Category. modules/nist_csf.py `roll_up`. */
export interface CsfCategory {
  id: string
  function: CsfFunctionId
  name: string
  description: string
  status: CsfStatus
  themes: string[]
  /** Why no evidence exists here. Non-null exactly when status is not_assessed. */
  reason: string | null
  counts: Record<string, number>
  total: number
  subcategories: CsfSubcategory[]
}

/** A CSF Function with its Categories. server/app.py `api_csf_function`. */
export interface CsfFunctionView {
  id: CsfFunctionId
  name: string
  /** The Function's outcome statement, verbatim from CSWP 29. */
  outcome: string
  counts: Record<string, number>
  total: number
  categories: CsfCategory[]
  categories_total: number
  categories_assessed: number
  categories_with_findings: number
  subcategories_total: number
  reference?: string
  doi?: string
}

/** The whole Core rolled up. server/app.py `api_csf`. */
export interface CsfView {
  framework: string
  reference: string
  doi: string
  functions: CsfFunctionView[]
  totals: {
    functions: number
    categories: number
    subcategories: number
    categories_assessable: number
    categories_not_assessed: number
    /** The corpus. `mapped` + `unmapped` account for it; they are never merged. */
    findings: number
    mapped: number
    unmapped: number
    unmapped_categories: Record<string, number>
  }
}

// ── Cyber Risk Quantification: the customer's own figures ───────────────────

/** One question. server/app.py `api_crq_parameters`, from modules/fair_loss_model.PARAMETERS. */
export interface CrqParameter {
  key: string
  label: string
  unit: 'currency' | 'percent' | 'hours' | 'count' | string
  group: string
  help: string
  feeds: string[]
}

/** A stored revision. INSERT-ONLY — a past figure must stay explainable. */
export interface CrqParameterSet {
  id: number
  landscape_id?: number
  answers: Record<string, number>
  currency: string
  note: string | null
  created_by: string | null
  created_at: string
}

export interface CrqParametersView {
  parameters: CrqParameter[]
  mam_modules: Record<string, { name: string; kind: string }>
  spread: Record<string, number>
  latest: CrqParameterSet | null
  history: CrqParameterSet[]
}

/** One priced FAIR-MAM component, with the arithmetic that produced it. */
export interface CrqPricedComponent {
  band: { min: number; likely: number; max: number }
  mam_module: string
  fair_form: string
  /** The sum in words. This travels with the figure and is always rendered. */
  basis: string
  inputs: string[]
}

export interface CrqPriced {
  components: Record<string, CrqPricedComponent>
  /** Modules NOT priced. Never zero — unknown. */
  unpriced: { module: string; needs: string }[]
  priced_modules: string[]
  spread: Record<string, number>
}

/** server/app.py `api_crq_quantify`. */
export interface CrqQuantifyResult {
  computed: boolean
  reason?: string
  portfolio: CrqPortfolioStats
  target_portfolio: CrqPortfolioStats
  reducible_ale_p90: number
  reducible_ale_mean: number
  priced: CrqPriced
  scale_factor: number | null
  simulations: number
  seed: number
  finding_count: number
  unrouted: number
  model_version?: number
  /** Whether the loss figures were the CUSTOMER'S. Absent or false means the
   *  shipped illustrative catalogue was used, and no currency total may be
   *  presented as this organisation's exposure — see lib/pricing.ts. */
  loss_model?: { applied?: boolean; priced_modules?: string[]
                 unpriced?: string[]; scale_factor?: number | null } | null
  /** What produced this figure. modules/fair_provenance.py. */
  provenance?: {
    catalogue: { path: string; version: string | null; currency: string | null
                 sha256: string | null; scenario_count: number | null }
    engine: { kind: string; path: string | null; sha256: string | null
              skipped: { path: string; reason: string }[] }
    model_version: number
    simulations: number
    seed: number
  }
}

export interface CrqPortfolioStats {
  ale_p10: number
  ale_p50: number
  ale_p90: number
  ale_p95: number
  ale_p99: number
  mean_ale: number
  iterations: number
  /** Share of simulated years with NO loss event. A P90 headline beside a $0
   *  median is true and reads as a typical year; this is what prevents that. */
  p_no_loss: number
  loss_exceedance?: { loss: number; probability: number }[]
}


/** One of the nine FAIR-CAM Loss Event Control functions. modules/fair_cam.py. */
export interface CrqControlFunction {
  id: string
  name: string
  domain: 'Prevention' | 'Detection' | 'Response'
  /** The FAIR factor this function moves. */
  factor: string
  definition: string
  findings: number
  weight: number
  severities: Record<string, number>
  themes: string[]
  confidence: 'high' | 'medium' | 'ambiguous' | 'none'
  /** assessed | clear | not_assessed — never two states. */
  status: string
  reason: string | null
}

export interface CrqControlsView {
  functions: CrqControlFunction[]
  domains: { domain: string; findings: number; weight: number; functions: string[] }[]
  variance_management: { findings: number; weight: number; themes: string[]; note: string }
  unattributed: { count: number; categories: string[]; note: string }
  severity_weights: Record<string, number>
  total_findings: number
}

// ── The twelve security domains ─────────────────────────────────────────────

/** What the product can EVER see in a domain. Fixed at author time, identical on
 *  every customer and every run. modules/domains.py. */
export type DomainReach = 'full' | 'partial' | 'config_only' | 'none'

/** What THIS run produced. Varies per scan. NOT the same question as reach —
 *  collapsing the two loses a real cell: a configuration-only domain that came
 *  back clean. */
export type DomainState = 'assessed' | 'clear' | 'not_supplied' | 'not_assessed'

export interface SecurityDomain {
  id: string
  /** The buyer's word, verbatim. The honesty lives in `scope`. */
  label: string
  reach: DomainReach
  /** The limit, rendered directly under the label and never omitted when set. */
  scope: string | null
  blurb: string | null
  state: DomainState
  total: number
  counts: Record<string, number>
  categories: string[]
  /** Only on the per-domain response. */
  findings?: { id: number; check_id: string; severity: string; title: string
               category: string; sid: string | null }[]
  categories_detail?: string[]
}

export interface DomainsView {
  domains: SecurityDomain[]
  unplaced: {
    counts: Record<string, number>
    total: number
    reasons: Record<string, string>
    note: string
  }
  totals: { domains: number; assessable: number; findings: number; placed: number }
}
