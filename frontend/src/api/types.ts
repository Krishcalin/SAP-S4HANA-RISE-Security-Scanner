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

export type DeploymentMode = 'on_prem' | 'rise_pce' | 'rise_tailored'

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
/** server/queries.py `list_systems` — sap_system.* plus the landscape join. */
export interface SapSystem {
  id: number
  landscape_id: number
  sid: string
  client: string
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
/** One hop of server/graph.py `_detail`. */
export interface PathHop {
  name: string
  required: boolean
  /** A CUT hop is one whose removal severs the path. A finding on a non-cut hop
   *  reduces exploitability without ending anything — the distinction is the
   *  whole value of the screen and must not be flattened in the UI. */
  is_cut: boolean
  why_cut: string | null
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
 *  `pct_compliant` is measured over CHECKS THAT ACTUALLY RAN, not the whole
 *  catalogue — scoring against every check ever written would let a customer
 *  improve their score by supplying fewer exports. Null when nothing ran. */
export interface DomainScore {
  category: string | null
  checks_run: number
  checks_failing: number
  pct_compliant: number | null
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
  requirements_covered: number
  covered: {
    requirement: string; tier: string; technology: string
    title: string; our_checks: string[]
  }[]
  not_covered: {
    requirement: string; tier: string; technology: string; title: string
  }[]
  beyond_baseline: string[]
  note: string
  meta: Record<string, unknown>
  our_checks: number
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
  page?: number
}
