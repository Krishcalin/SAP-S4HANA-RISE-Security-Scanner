-- Copyright (c) 2026 Krishnendu De. All Rights Reserved.
--
-- Author : Krishnendu De
-- Coding Assistance : Claude Code
-- Code Security Assistance : Code QL

-- =====================================================================
--  MonitorRisk — schema
--  PostgreSQL 16
--
--  SINGLE-TENANT PER DEPLOYMENT (decided 2026-08-05).
--
--  One deployment serves one customer. There is deliberately no tenant_id
--  column: carrying one "just in case" invites row filters that are written
--  but never enforced, which is worse than not having the column.
--
--  Optionality is preserved cheaply instead, by the `landscape` level below.
--  A consultancy can hold several customers' landscapes in one deployment
--  today, and a future multi-tenant build is one ALTER plus a backfill from
--  landscape -> tenant, because every row already reaches a landscape through
--  sap_system. What that would NOT give us is cross-customer benchmarking,
--  which the research says not to promise anyway (a benchmark over a handful
--  of customers is fiction).
-- =====================================================================

-- ---------------------------------------------------------------------
--  Landscape and systems
-- ---------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS landscape (
    id              bigserial PRIMARY KEY,
    name            text        NOT NULL UNIQUE,
    description     text,
    -- Which contract the responsibility mapping is being read against.
    -- Pinned per landscape, not global: SAP versions the Roles &
    -- Responsibilities document roughly quarterly and the effective split is
    -- negotiated per customer. See docs/RISE_SECURITY_MODEL.md section 0 —
    -- the category VOCABULARY differs between PCE and the tailored option, so
    -- a hard-coded matrix would be wrong for half of all customers.
    -- Mirrors modules/deployment_modes.py DEPLOYMENT_MODES, which SQL cannot
    -- import; tests/test_deployment_modes.py asserts the two agree. Widen HERE
    -- and in the migration block below — this line alone is a no-op on every
    -- database that already exists.
    deployment_mode text        NOT NULL DEFAULT 'on_prem'
                    CHECK (deployment_mode IN ('on_prem', 'rise_pce', 'rise_tailored', 'rise_ecc')),
    rr_version      text,
    created_at      timestamptz NOT NULL DEFAULT now()
);

-- A ROW HERE IS "A THING FINDINGS ATTACH TO", NOT "AN ABAP SYSTEM".
-- Decision D8. A SaaS tenant — SuccessFactors, Concur, IAS, a BTP subaccount —
-- is a row in THIS table carrying a platform and an external key, not a landscape
-- of its own. A landscape is the customer's estate; a tenant is a thing inside it.
-- Modelling a tenant as a landscape would fork every query that already scopes by
-- system.
--
-- WHICH IS WHY sid AND client ARE NULLABLE. They were NOT NULL, which is correct
-- for ABAP and impossible for a tenant that has neither. The discriminator CHECK
-- below is what keeps that from becoming a licence for half-populated rows: an
-- abap row must still have both, and a non-abap row must have an external key.
CREATE TABLE IF NOT EXISTS sap_system (
    id              bigserial PRIMARY KEY,
    landscape_id    bigint      NOT NULL REFERENCES landscape(id) ON DELETE CASCADE,
    -- Mirrors the migration block below. Change BOTH — see "Constraint migrations".
    platform        text        NOT NULL DEFAULT 'abap',
    -- The tenant's own identifier, opaque to us: a SuccessFactors company id, a
    -- Concur entity id, a BTP subaccount id. NULL for ABAP.
    external_key    text,
    sid             text,
    client          text,
    -- prod/qa/dev/sandbox drives more than a label: a trust edge FROM a lower
    -- tier INTO production is the single most load-bearing attack-path fact we
    -- can derive, and it is not computable without this column.
    tier            text        NOT NULL DEFAULT 'unknown'
                    CHECK (tier IN ('prod', 'qa', 'dev', 'sandbox', 'unknown')),
    product         text,
    release         text,
    kernel_patch    text,
    btp_subaccount  text,
    -- Honest FAIR calibration input. Onapsis concedes CVSS cannot express this
    -- ("not all systems are the same"); a sandbox and a production ledger must
    -- not carry the same exposure band.
    criticality     text        NOT NULL DEFAULT 'medium'
                    CHECK (criticality IN ('critical', 'high', 'medium', 'low')),
    -- Reachability cannot be validated from an offline export, so the customer
    -- declares it. A small input that upgrades every internet-facing path.
    exposure_zone   text        NOT NULL DEFAULT 'unknown'
                    CHECK (exposure_zone IN ('internet', 'dmz', 'internal', 'isolated', 'unknown')),
    owner           text,
    tags            text[]      NOT NULL DEFAULT '{}',
    created_at      timestamptz NOT NULL DEFAULT now(),
    -- KEPT, deliberately, rather than replaced by a partial index. server/cli.py's
    -- add-system names it as an ON CONFLICT arbiter, and PostgreSQL cannot infer an
    -- arbiter from a PARTIAL index unless the INSERT repeats the predicate — so
    -- replacing this would break that command at runtime with SQLSTATE 42P10, on a
    -- path no test executes. ABAP rows always have a sid (the discriminator below
    -- enforces it), so this keeps doing its job; tenant rows have NULL sid, never
    -- collide here, and are deduplicated by sap_system_tenant_key instead.
    UNIQUE (landscape_id, sid, client),
    -- Mirrors the migration block. Change BOTH.
    CONSTRAINT sap_system_platform_check
        CHECK (platform IN ('abap', 'btp', 'successfactors', 'concur', 'ias',
                            'cloud_alm', 'ariba', 'fieldglass')),
    -- `<> ''` AND NOT `IS NOT NULL`. An empty-string sid satisfies IS NOT NULL and
    -- normalises to the same canonical fingerprint string as a NULL one, so a
    -- nullability-only discriminator would leave the exact collision D8 exists to
    -- remove. Empty sids are insertable today: add-system takes sid positionally
    -- with no validation.
    CONSTRAINT sap_system_shape_check CHECK (
        (platform =  'abap' AND sid <> '' AND client <> ''
                           AND sid IS NOT NULL AND client IS NOT NULL)
     OR (platform <> 'abap' AND external_key <> '' AND external_key IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS sap_system_landscape_idx ON sap_system (landscape_id);
CREATE INDEX IF NOT EXISTS sap_system_tags_idx      ON sap_system USING gin (tags);
-- THE TENANT UNIQUENESS INDEX IS NOT HERE. It is defined in the constraint-
-- migrations section at the end of this file, and this note exists because here is
-- where you would look for it and putting it here is a real, tested mistake: its
-- predicate names `platform`, and on an UPGRADE this line is reached before the
-- ADD COLUMN that creates that column, so the whole migration dies with
-- `column "platform" does not exist`. It passes a fresh install, which is what
-- makes it easy to ship. The migration section runs on fresh installs too, so
-- defining it once down there covers both paths.

-- ---------------------------------------------------------------------
--  Check catalogue  (the DEFINITION half of the definition/occurrence split)
-- ---------------------------------------------------------------------
--  Splitting the shared catalogue from the per-object occurrence is what makes
--  check_id a foreign key rather than an identity. It is also what the
--  incumbent's own published data model does, and it is the direct fix for the
--  measured collisions (USR-001 fires four times in one run).

CREATE TABLE IF NOT EXISTS check_definition (
    check_id         text PRIMARY KEY,
    title            text NOT NULL,
    category         text,
    module           text,
    default_severity text,
    -- The team that fixes it. Copied from an incumbent mechanic that makes a
    -- large check catalogue consumable: findings route to a team, not a person.
    owning_team      text CHECK (owning_team IN
                       ('basis', 'authorizations', 'development', 'integration',
                        'data_protection', 'identity', 'unassigned')),
    -- Who CAN act, per the contract. Four-state, because a binary customer/SAP
    -- flag misrepresents the Packaged Services category — which is exactly
    -- where SAP's own paid competitors to us sit.
    responsibility   text CHECK (responsibility IN
                       ('customer', 'customer_unless_purchased', 'sap_on_request',
                        'sap_only', 'unknown')),
    -- SAP Security Baseline requirement ID (PWDPOL-A, RFCGW-A, CRITAU-A...).
    -- Mapping to SAP's own vocabulary is far more defensible in an audit than a
    -- house-brand control name.
    baseline_req_id  text,
    -- DELIBERATELY ABSENT: any SAP Roles & Responsibilities line-item ID.
    -- Tagging checks to the contract task they discharge is a good idea, but
    -- the ID-to-task pairing in the published PDFs drifts under text
    -- extraction and is currently UNVERIFIED. Adding the column would invite
    -- populating it. See docs/RISE_SECURITY_MODEL.md section 0.
    cve              text,
    cvss             numeric(3,1),
    risk_narrative   text,
    remediation      text,
    references_json  jsonb NOT NULL DEFAULT '[]'::jsonb,
    updated_at       timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS check_definition_baseline_idx
    ON check_definition (baseline_req_id) WHERE baseline_req_id IS NOT NULL;

-- ---------------------------------------------------------------------
--  Scan runs
-- ---------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS scan_run (
    id             bigserial PRIMARY KEY,
    landscape_id   bigint      NOT NULL REFERENCES landscape(id) ON DELETE CASCADE,
    system_id      bigint      REFERENCES sap_system(id) ON DELETE SET NULL,
    status         text        NOT NULL DEFAULT 'pending'
                   CHECK (status IN ('pending', 'parsing', 'scanning', 'deriving',
                                     'complete', 'failed', 'cancelled')),
    -- Duplicate detection that INFORMS rather than blocks: re-uploading an
    -- identical bundle is a legitimate act (it proves nothing changed), so we
    -- surface it instead of refusing it.
    content_sha    text,
    uploaded_by    text,
    upload_name    text,
    started_at     timestamptz NOT NULL DEFAULT now(),
    finished_at    timestamptz,
    -- Progress, because a 23-module run must not sit on the request path and a
    -- user watching it must be able to see where it is — and cancel it.
    progress_done  integer     NOT NULL DEFAULT 0,
    progress_total integer     NOT NULL DEFAULT 0,
    cancel_requested boolean   NOT NULL DEFAULT false,
    error          text,
    -- Not cosmetic. A missing export file loads as None and its checks
    -- self-skip SILENTLY, so a partial upload produces a clean-looking report.
    -- That is a correctness defect, not a missing feature, and this column plus
    -- module_status below is the fix.
    coverage       jsonb       NOT NULL DEFAULT '{}'::jsonb,
    module_status  jsonb       NOT NULL DEFAULT '{}'::jsonb,
    scanner_version text
);

CREATE INDEX IF NOT EXISTS scan_run_landscape_idx ON scan_run (landscape_id, started_at DESC);
CREATE INDEX IF NOT EXISTS scan_run_system_idx    ON scan_run (system_id, started_at DESC);
CREATE INDEX IF NOT EXISTS scan_run_sha_idx       ON scan_run (content_sha) WHERE content_sha IS NOT NULL;

-- ---------------------------------------------------------------------
--  Findings
-- ---------------------------------------------------------------------
--  finding is the DURABLE row — one per distinct defect, carrying the whole
--  lifecycle and the whole history. finding_observation records that a given
--  run saw it. That split is what makes the mitigation journey computable:
--  "resolved" is the absence of an observation in the latest run, not a
--  deletion, so a regression re-opens the SAME row and its age is continuous.

CREATE TABLE IF NOT EXISTS finding (
    id               bigserial PRIMARY KEY,
    landscape_id     bigint NOT NULL REFERENCES landscape(id) ON DELETE CASCADE,
    system_id        bigint REFERENCES sap_system(id) ON DELETE SET NULL,
    fingerprint      text   NOT NULL,
    check_id         text   NOT NULL REFERENCES check_definition(check_id),
    client           text,
    -- How much to trust cross-run matching for THIS row. Stored, not inferred,
    -- because a journey feature that cannot explain a non-match is not
    -- trustworthy: 'objects' is structural, 'display' holds only while the
    -- module's formatting holds, 'check_only' is a correctly coarse aggregate.
    fingerprint_basis text NOT NULL DEFAULT 'check_only'
                     CHECK (fingerprint_basis IN ('objects', 'display', 'check_only')),
    scope            text   NOT NULL DEFAULT 'object'
                     CHECK (scope IN ('object', 'aggregate')),
    subject          jsonb  NOT NULL DEFAULT '[]'::jsonb,

    severity         text,
    priority_tier    text,
    priority_score   integer,
    -- The prioritiser's named factors. Kept as data so the UI can show WHY a
    -- finding ranks where it does — explainability is the product, and it
    -- works on findings CVSS cannot score at all.
    priority_factors jsonb  NOT NULL DEFAULT '[]'::jsonb,

    state            text   NOT NULL DEFAULT 'open'
                     CHECK (state IN ('open', 'submitted_to_provider', 'mitigated',
                                      'accepted', 'false_positive', 'resolved')),
    -- What the UI renders, and a SEPARATE axis from check_definition.responsibility.
    -- In RISE a customer can SEE a bad profile parameter and cannot fix it; a
    -- report that says "change this" is unactionable noise.
    remediation_owner text  NOT NULL DEFAULT 'customer_fixable'
                     CHECK (remediation_owner IN ('customer_fixable', 'ticket_to_sap',
                                                  'provider_owned', 'not_assessable')),
    assignee         text,
    owning_team      text,
    due_date         date,
    provider_ticket_ref text,

    first_seen_run   bigint REFERENCES scan_run(id) ON DELETE SET NULL,
    last_seen_run    bigint REFERENCES scan_run(id) ON DELETE SET NULL,
    first_seen_at    timestamptz NOT NULL DEFAULT now(),
    last_detected_at timestamptz NOT NULL DEFAULT now(),
    resolved_at      timestamptz,
    -- Counts open->resolved->open cycles. A finding that keeps coming back is a
    -- process failure, and it is invisible if you only store current state.
    regression_count integer NOT NULL DEFAULT 0,

    -- Risk acceptance, copied wholesale from the incumbent's model including
    -- the expiry. An acceptance that silently never expires is itself an audit
    -- finding, so expiry is not optional and expired_acceptance is derived.
    accepted_by      text,
    acceptance_reason text,
    acceptance_from  date,
    acceptance_due   date,

    -- A disputed finding must become tuning data rather than noise, which
    -- requires the reason to be mandatory at the API layer.
    false_positive_reason text,

    transitioned_by  text,
    last_transition_at timestamptz,

    UNIQUE (landscape_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS finding_system_state_idx ON finding (system_id, state);
CREATE INDEX IF NOT EXISTS finding_check_idx        ON finding (check_id);
CREATE INDEX IF NOT EXISTS finding_open_idx         ON finding (landscape_id, priority_tier)
    WHERE state IN ('open', 'submitted_to_provider');
CREATE INDEX IF NOT EXISTS finding_subject_idx      ON finding USING gin (subject);

-- NOTE: there was a `finding_effective` view here that computed `expired_acceptance`
-- and `days_open` over `SELECT f.*`. It has been REMOVED, and should not come back
-- in that form.
--
-- `CREATE OR REPLACE VIEW` cannot change a view's column list, and `f.*` expands to
-- whatever the table currently has — so the moment any ALTER TABLE added a column to
-- `finding`, re-running this file failed with "cannot change name of view column".
-- That broke the documented upgrade path (re-run schema.sql), and it broke it
-- silently until someone actually upgraded.
--
-- Nothing used the view: server/queries.py computes both derivations inline where
-- they are needed. If a view is ever wanted here, enumerate its columns explicitly
-- and DROP it before recreating.

CREATE TABLE IF NOT EXISTS finding_observation (
    id              bigserial PRIMARY KEY,
    finding_id      bigint NOT NULL REFERENCES finding(id) ON DELETE CASCADE,
    scan_run_id     bigint NOT NULL REFERENCES scan_run(id) ON DELETE CASCADE,
    severity        text,
    title           text,
    description     text,
    -- The full member list for THIS run. For an aggregate finding this is the
    -- part that legitimately changes run to run while identity stays put.
    affected_items  jsonb NOT NULL DEFAULT '[]'::jsonb,
    affected_objects jsonb NOT NULL DEFAULT '[]'::jsonb,
    affected_count  integer NOT NULL DEFAULT 0,
    details         jsonb NOT NULL DEFAULT '{}'::jsonb,
    observed_at     timestamptz NOT NULL DEFAULT now(),
    UNIQUE (finding_id, scan_run_id)
);

CREATE INDEX IF NOT EXISTS finding_observation_run_idx ON finding_observation (scan_run_id);

-- Every lifecycle transition, for the auditor and for MTTR.
CREATE TABLE IF NOT EXISTS finding_transition (
    id           bigserial PRIMARY KEY,
    finding_id   bigint NOT NULL REFERENCES finding(id) ON DELETE CASCADE,
    scan_run_id  bigint REFERENCES scan_run(id) ON DELETE SET NULL,
    from_state   text,
    to_state     text NOT NULL,
    actor        text,
    reason       text,
    occurred_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS finding_transition_finding_idx
    ON finding_transition (finding_id, occurred_at DESC);

-- ---------------------------------------------------------------------
--  Graph  (Phase 4 — created now so the ingest can populate nodes from day one)
-- ---------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS graph_node (
    id            bigserial PRIMARY KEY,
    landscape_id  bigint NOT NULL REFERENCES landscape(id) ON DELETE CASCADE,
    node_key      text   NOT NULL,
    type          text   NOT NULL,
    name          text   NOT NULL,
    system_id     bigint REFERENCES sap_system(id) ON DELETE SET NULL,
    client        text,
    qualifier     text,
    finding_count integer NOT NULL DEFAULT 0,
    first_seen_run bigint REFERENCES scan_run(id) ON DELETE SET NULL,
    last_seen_run  bigint REFERENCES scan_run(id) ON DELETE SET NULL,
    UNIQUE (landscape_id, node_key)
);

CREATE TABLE IF NOT EXISTS graph_edge (
    id           bigserial PRIMARY KEY,
    landscape_id bigint NOT NULL REFERENCES landscape(id) ON DELETE CASCADE,
    from_node    bigint NOT NULL REFERENCES graph_node(id) ON DELETE CASCADE,
    to_node      bigint NOT NULL REFERENCES graph_node(id) ON DELETE CASCADE,
    type         text   NOT NULL,
    check_id     text   REFERENCES check_definition(check_id),
    -- configured = the export says the relationship exists.
    -- used       = it was actually exercised (a destination in a gateway log, a
    --              role whose holders logged on recently). Derivable offline and
    --              a genuine differentiator.
    provenance   text   NOT NULL DEFAULT 'configured'
                 CHECK (provenance IN ('configured', 'used')),
    -- We can never validate reachability without a connection, so every edge
    -- says so and the UI repeats it. A buyer who has seen Wiz WILL ask
    -- "did you actually reach it?" — the answer must be prepared, not improvised.
    confidence   text   NOT NULL DEFAULT 'derived_from_config'
                 CHECK (confidence IN ('derived_from_config', 'observed')),
    -- SAP-managed RFC destinations are real trust relationships but are not the
    -- customer's to fix. Flagging one as a customer misconfiguration wastes
    -- their time and costs us credibility on the first report.
    owner        text   NOT NULL DEFAULT 'unknown'
                 CHECK (owner IN ('customer', 'sap', 'unknown')),
    attributes   jsonb  NOT NULL DEFAULT '{}'::jsonb,
    first_seen_run bigint REFERENCES scan_run(id) ON DELETE SET NULL,
    last_seen_run  bigint REFERENCES scan_run(id) ON DELETE SET NULL,
    UNIQUE (landscape_id, from_node, to_node, type)
);

CREATE INDEX IF NOT EXISTS graph_edge_from_idx ON graph_edge (from_node);
CREATE INDEX IF NOT EXISTS graph_edge_to_idx   ON graph_edge (to_node);

CREATE TABLE IF NOT EXISTS attack_path (
    id            bigserial PRIMARY KEY,
    landscape_id  bigint NOT NULL REFERENCES landscape(id) ON DELETE CASCADE,
    template_id   text   NOT NULL,
    path_key      text   NOT NULL,
    entry_node    bigint REFERENCES graph_node(id) ON DELETE SET NULL,
    target_node   bigint REFERENCES graph_node(id) ON DELETE SET NULL,
    -- The path ends at a FAIR scenario, so it ends at a currency figure.
    fair_scenario text,
    severity      text,
    first_seen    timestamptz NOT NULL DEFAULT now(),
    last_seen     timestamptz NOT NULL DEFAULT now(),
    closed_at     timestamptz,
    -- THE product column. "This path was severed on 12 Sep when the S_RFCACL
    -- wildcard was removed from ZBASIS_SUPPORT" is a sentence no incumbent's
    -- PDF report can produce.
    closed_by_edge bigint REFERENCES graph_edge(id) ON DELETE SET NULL,
    -- Stored paths go stale when the path RULESET changes, not only when the
    -- data does. Fingerprinting the live ruleset lets the console say so
    -- instead of silently showing derivations computed under older rules.
    ruleset_fingerprint text,
    UNIQUE (landscape_id, path_key)
);

CREATE TABLE IF NOT EXISTS attack_path_edge (
    path_id bigint  NOT NULL REFERENCES attack_path(id) ON DELETE CASCADE,
    edge_id bigint  NOT NULL REFERENCES graph_edge(id) ON DELETE CASCADE,
    hop     integer NOT NULL,
    -- Drives the mitigate-vs-additional split: a cut edge appears on EVERY
    -- variant of the path, so removing it disconnects the path. Everything else
    -- only reduces risk. That distinction, not the picture, is what makes a
    -- path actionable.
    is_cut  boolean NOT NULL DEFAULT false,
    PRIMARY KEY (path_id, edge_id)
);

CREATE TABLE IF NOT EXISTS attack_path_finding (
    path_id    bigint NOT NULL REFERENCES attack_path(id) ON DELETE CASCADE,
    finding_id bigint NOT NULL REFERENCES finding(id) ON DELETE CASCADE,
    PRIMARY KEY (path_id, finding_id)
);

-- ---------------------------------------------------------------------
--  Risk quantification
-- ---------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS crq_result (
    id            bigserial PRIMARY KEY,
    scan_run_id   bigint NOT NULL REFERENCES scan_run(id) ON DELETE CASCADE,
    scenario_id   text,          -- NULL = the portfolio roll-up
    ale_p10       numeric,
    ale_p50       numeric,
    ale_p90       numeric,
    ale_mean      numeric,
    -- Disclosing what the model did NOT price is what separates this from
    -- vendor hand-waving, and a buyer with a risk function will test it.
    unrouted_count integer NOT NULL DEFAULT 0,
    -- FAIR runs on the UNFILTERED finding set, so a display filter can never
    -- move the currency figure. Recorded to prove it.
    input_finding_count integer NOT NULL DEFAULT 0,
    detail        jsonb NOT NULL DEFAULT '{}'::jsonb,
    computed_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS crq_result_run_idx ON crq_result (scan_run_id);

-- ---------------------------------------------------------------------
--  Access control and audit
-- ---------------------------------------------------------------------
--  Single-tenant, so the row filter is by LANDSCAPE and SYSTEM rather than by
--  tenant. Per-system scoping exists from day one because retrofitting a row
--  filter is painful and because "this user may see only these systems" is a
--  capability the incumbent shipped only in 2026.

CREATE TABLE IF NOT EXISTS app_user (
    id            bigserial PRIMARY KEY,
    username      text NOT NULL UNIQUE,
    display_name  text,
    password_hash text NOT NULL,
    role          text NOT NULL DEFAULT 'viewer'
                  CHECK (role IN ('admin', 'analyst', 'viewer')),
    is_active     boolean NOT NULL DEFAULT true,
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_login_at timestamptz
);

-- Absence of rows here means "all systems". Presence restricts.
CREATE TABLE IF NOT EXISTS user_system_scope (
    user_id   bigint NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    system_id bigint NOT NULL REFERENCES sap_system(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, system_id)
);

CREATE TABLE IF NOT EXISTS session (
    token      text PRIMARY KEY,
    user_id    bigint NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    user_agent text
);

CREATE INDEX IF NOT EXISTS session_user_idx ON session (user_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id          bigserial PRIMARY KEY,
    actor       text,
    action      text NOT NULL,
    object_type text,
    object_id   text,
    detail      jsonb NOT NULL DEFAULT '{}'::jsonb,
    occurred_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS audit_log_time_idx ON audit_log (occurred_at DESC);

-- ---------------------------------------------------------------------
--  Saved views  (Phase 2)
-- ---------------------------------------------------------------------
--  Reporting is READ ACCESS, not file production. Each audience gets a durable,
--  permission-scoped URL — a Basis worklist, an auditor evidence view, an
--  executive summary — rather than a document somebody must fetch and forward.
--  The alternative is what an incumbent's customers actually resorted to: batch
--  scripts re-posting files to SharePoint because reports could not be delivered
--  per audience from the tool itself.
--
--  A saved view stores FILTERS, never rows. Opening one re-runs the query through
--  the caller's own row scope, so sharing a link can never widen access: two
--  people opening the same URL each see the systems they are entitled to.

CREATE TABLE IF NOT EXISTS saved_view (
    id           bigserial PRIMARY KEY,
    slug         text NOT NULL UNIQUE,
    name         text NOT NULL,
    description  text,
    -- which screen the stored filters apply to
    kind         text NOT NULL DEFAULT 'findings'
                 CHECK (kind IN ('findings', 'trend', 'coverage')),
    filters      jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_by   text,
    -- Shared views appear in everyone's list; private ones only for their owner.
    is_shared    boolean NOT NULL DEFAULT true,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS saved_view_kind_idx ON saved_view (kind, name);

-- ---------------------------------------------------------------------
--  Notifications  (Phase 2)
-- ---------------------------------------------------------------------
--  Queued in the database, never sent inline. A scan that cannot reach a mail
--  relay must still complete and store its findings — the notification is the
--  least important thing happening in that transaction.

CREATE TABLE IF NOT EXISTS notification (
    id             bigserial PRIMARY KEY,
    scan_run_id    bigint REFERENCES scan_run(id) ON DELETE CASCADE,
    kind           text NOT NULL,
    severity       text,
    subject        text NOT NULL,
    body           text NOT NULL,
    payload        jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at     timestamptz NOT NULL DEFAULT now(),
    delivered_at   timestamptz,
    delivery_error text
);

CREATE INDEX IF NOT EXISTS notification_undelivered_idx
    ON notification (created_at) WHERE delivered_at IS NULL;

-- ---------------------------------------------------------------------
--  Phase 2 columns on existing tables
-- ---------------------------------------------------------------------
--  Added as ALTERs rather than edited into the CREATEs above, so an existing
--  deployment upgrades simply by re-running this file.

-- Account self-service.
--
-- `must_change_password` exists because of how the first admin is created: the
-- container has no TTY, so `create-user --generate` mints a password and prints it
-- to a terminal, where it survives in scrollback, in `docker compose logs` and in
-- whatever recorded the session. A machine-generated password is a BOOTSTRAP
-- credential, not a chosen one, so the account is forced to replace it at first
-- login rather than trusted to remember.
ALTER TABLE app_user ADD COLUMN IF NOT EXISTS must_change_password boolean
    NOT NULL DEFAULT false;
ALTER TABLE app_user ADD COLUMN IF NOT EXISTS password_changed_at timestamptz;

ALTER TABLE finding ADD COLUMN IF NOT EXISTS priority_rationale text;
-- When the SLA clock started. Deliberately distinct from first_seen_at:
-- re-prioritising a finding restarts its window, and an "overdue" count computed
-- from first_seen would blame the customer for a tier we assigned yesterday.
ALTER TABLE finding ADD COLUMN IF NOT EXISTS sla_started_at timestamptz;

CREATE INDEX IF NOT EXISTS finding_due_idx ON finding (due_date)
    WHERE state IN ('open', 'submitted_to_provider') AND due_date IS NOT NULL;
CREATE INDEX IF NOT EXISTS finding_tier_idx ON finding (landscape_id, priority_tier)
    WHERE state IN ('open', 'submitted_to_provider');

-- ---------------------------------------------------------------------
--  Phase 4 columns
-- ---------------------------------------------------------------------

-- The renderable shape of an instantiated path: its hops, which of them are cuts,
-- and the evidence behind each. Stored rather than recomputed on read so the path
-- page can never disagree with the row that carries the path's history.
ALTER TABLE attack_path ADD COLUMN IF NOT EXISTS detail jsonb NOT NULL DEFAULT '{}'::jsonb;

-- ---------------------------------------------------------------------
--  Code findings
-- ---------------------------------------------------------------------
-- Two columns, and only two. The snippet and the source->sink taint trace do NOT
-- get columns: they live in `finding_observation.details`, which already exists
-- and is already populated from the auditor's `details` dict. Both describe what
-- the code looked like in THAT run, which is exactly what a per-observation jsonb
-- is for -- a column on `finding` would claim they are properties of the durable
-- defect, and they are not.

-- The catalogue already carries `cve` and `cvss` but had nowhere to put a CWE,
-- and every rule in the ABAP corpus ships one. It belongs on the definition
-- because it is a property of the CHECK, not of an occurrence.
ALTER TABLE check_definition ADD COLUMN IF NOT EXISTS cwe text;

-- Taint confidence CANNOT live on check_definition: the same rule is `confirmed`
-- in one program and `pattern-only` in another, so it varies per occurrence. It
-- is the single most decision-relevant field a SAST finding has -- "our regex
-- matched" and "tainted input provably reaches this sink" are not the same claim
-- and must never render identically.
ALTER TABLE finding ADD COLUMN IF NOT EXISTS taint_confidence text
    CHECK (taint_confidence IN ('confirmed', 'tentative', 'pattern-only'));

-- Reachability from Phase 4a: whether anything in the estate can reach the object
-- the finding is about. NULL means no code-inventory evidence either way, which is
-- a third state and must not be read as 'unreachable'.
ALTER TABLE finding ADD COLUMN IF NOT EXISTS reachability text
    CHECK (reachability IN ('reachable', 'unreachable', 'unknown'));

CREATE INDEX IF NOT EXISTS attack_path_open_idx
    ON attack_path (landscape_id, severity) WHERE closed_at IS NULL;
CREATE INDEX IF NOT EXISTS attack_path_closed_idx
    ON attack_path (closed_at DESC) WHERE closed_at IS NOT NULL;

-- ---------------------------------------------------------------------
--  Second factor (TOTP), recovery codes, and the attempt budget
-- ---------------------------------------------------------------------
-- A SEPARATE TABLE, NOT COLUMNS ON app_user, AND THAT IS THE LOAD-BEARING PART.
-- `auth.resolve_session` selects `u.*` and `api_account` does `SELECT *`, so
-- anything added to app_user rides into every route handler's `current_user` and
-- into the account payload -- a secret one column away from being serialised.
--
-- The second reason is the one that actually bites. A single `totp_secret` column
-- cannot hold a PENDING enrolment and a LIVE one at the same time, so `begin`
-- would have to overwrite the live secret to offer a new QR. Anyone holding a
-- stolen session could then either replace the factor with one in their own
-- authenticator -- locking the owner out of their own account -- or clear it and
-- silently downgrade to password-only, which is the exact outcome a second factor
-- is bought to prevent. It is not only an attack: a user re-enrolling on a new
-- phone whose battery dies before they type the code would destroy their working
-- factor. `secret` and `pending_secret` are therefore distinct columns, `begin`
-- writes only the pending pair, and `confirm` promotes one to the other.
--
-- `last_counter` is NOT NULL DEFAULT -1 rather than nullable: it is compared with
-- `<` on every sign-in, and a NULL there would be an `int(None)` on the login path
-- or, worse, a comparison that quietly never matches.
CREATE TABLE IF NOT EXISTS app_totp (
    user_id        bigint PRIMARY KEY REFERENCES app_user(id) ON DELETE CASCADE,
    secret         text,          -- base32; the LIVE factor, only ever set by confirm
    pending_secret text,          -- base32; an enrolment nobody has proved yet
    pending_at     timestamptz,   -- when the pending secret was minted (it expires)
    confirmed_at   timestamptz,   -- NULL => not a live factor, whatever `secret` holds
    last_counter   bigint NOT NULL DEFAULT -1,   -- replay floor; see server/totp.py
    created_at     timestamptz NOT NULL DEFAULT now()
);

-- Single-use fallbacks for a lost or wiped phone. This product deliberately has no
-- self-service password reset, so without these a lost device is a dead account and
-- -- for the only administrator -- a dead deployment.
--
-- Only the hash is stored: a leaked table must not yield usable codes. UNIQUE on
-- (user_id, code_hash) is not decoration -- it is what makes "consume exactly once"
-- expressible as a single conditional UPDATE rather than a read-then-write race.
CREATE TABLE IF NOT EXISTS recovery_code (
    id         bigserial PRIMARY KEY,
    user_id    bigint NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    code_hash  text NOT NULL,
    used_at    timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (user_id, code_hash)
);

-- Partial index: every lookup is for a code that has NOT been spent, and the spent
-- rows are kept only so a used code cannot be silently re-minted.
CREATE INDEX IF NOT EXISTS recovery_code_live_idx
    ON recovery_code (user_id) WHERE used_at IS NULL;

-- The attempt budget. A six-digit code accepted across a +/-1 step window is 10^6
-- possibilities with a ~90-second life; without a cap, unlimited guesses make the
-- second factor decorative. There is no Redis and no rate-limit middleware in this
-- deployment by design, so the budget lives where the rest of the state does --
-- which also means it survives a restart and is shared by every worker.
--
-- `scope` is a prefixed key: 'ip:<addr>', 'pw:<username>', '2fa:<username>'. The
-- password and second-factor budgets are counted SEPARATELY on purpose: a mistyped
-- code must not burn the password budget, and someone who knows a password must not
-- be able to lock the real owner out of it. Blocks self-clear -- an attacker buys a
-- delay, never a support ticket -- so nothing here ever sets is_active = false.
CREATE TABLE IF NOT EXISTS auth_attempt (
    scope         text PRIMARY KEY,
    failures      integer NOT NULL DEFAULT 0,
    blocked_until timestamptz,
    updated_at    timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------
--  Constraint migrations
-- ---------------------------------------------------------------------
-- ⚠️ READ THIS BEFORE EDITING ANY `CHECK` LIST ABOVE. IT WILL NOT DO WHAT YOU
-- THINK.
--
-- `CREATE TABLE IF NOT EXISTS` is a NO-OP on a table that already exists. It
-- reports success and changes nothing. So editing a CHECK inside one of the
-- CREATE statements above alters the constraint on a FRESH database and leaves
-- every DEPLOYED database on the old rule — while CI, which builds from empty,
-- goes green. Demonstrated on PostgreSQL 16:
--
--     CREATE TABLE IF NOT EXISTS demo (m text CHECK (m IN ('a','b')));
--     CREATE TABLE IF NOT EXISTS demo (m text CHECK (m IN ('a','b','c')));
--       NOTICE:  relation "demo" already exists, skipping
--       CREATE TABLE                       <- reports success
--     INSERT INTO demo VALUES ('c');
--       ERROR:  violates check constraint "demo_m_check"   <- old rule still live
--
-- That matters because the next thing this schema needs is a wider vocabulary:
-- new deployment modes for ECC, and a platform column for non-ABAP tenants. Both
-- are CHECK-list changes, and both would have shipped as no-ops.
--
-- THE IDIOM. Any constraint whose value list is expected to grow is re-asserted
-- HERE, by explicit name, as DROP IF EXISTS followed by ADD. That pair is
-- idempotent, so it survives this file being re-run — which is the documented
-- upgrade path — and it is the ONLY place such a list may be edited. Editing the
-- copy inside the CREATE above and not here changes nothing on an upgrade;
-- editing here and not above changes nothing on a fresh install. Change both.
--
-- If an ADD fails, that is the intended behaviour: existing rows violate the new
-- rule and somebody must decide what happens to them. A migration that silently
-- widens around bad data is how the data stops meaning anything.
--
-- `.github/workflows/tests.yml` has a `schema-upgrade` job that builds a database
-- from the PREVIOUS commit's schema.sql, applies this one, and asserts the
-- constraint actually moved. Without that job this section would be untested
-- ceremony.

-- Widened for `rise_ecc` (decision D7). The name order is load-bearing: four call
-- sites decide ECS governance with startswith("rise"), so `ecc_rise` would have
-- disabled every ECS rule for a system contractually bound by them, silently.
-- The list mirrors modules/deployment_modes.py; tests/test_deployment_modes.py
-- asserts they agree.
ALTER TABLE landscape DROP CONSTRAINT IF EXISTS landscape_deployment_mode_check;
ALTER TABLE landscape ADD CONSTRAINT landscape_deployment_mode_check
    CHECK (deployment_mode IN ('on_prem', 'rise_pce', 'rise_tailored', 'rise_ecc'));

-- ---------------------------------------------------------------------
--  sap_system becomes able to hold a SaaS tenant  (decision D8)
-- ---------------------------------------------------------------------
--
-- ORDER MATTERS HERE AND NOWHERE ELSE IN THIS FILE. Every statement that mentions
-- `platform` must come AFTER the ADD COLUMN that creates it. Writing the tenant
-- index up beside the other sap_system indexes — the natural place — passes a
-- fresh install and fails every upgrade with `column "platform" does not exist`.
--
-- NOTE THE ABSENT `CHECK` ON THE ADD COLUMN. `ADD COLUMN IF NOT EXISTS` carries
-- the SAME silent-no-op trap as `CREATE TABLE IF NOT EXISTS` — the column is
-- skipped and any inline CHECK with it — and the warning above names only CREATE
-- TABLE. Two live instances of that mistake already exist in this file
-- (`taint_confidence`, `reachability`): neither list can be widened on a deployed
-- database. So the platform vocabulary lives in a NAMED constraint below instead.

ALTER TABLE sap_system ADD COLUMN IF NOT EXISTS platform     text NOT NULL DEFAULT 'abap';
ALTER TABLE sap_system ADD COLUMN IF NOT EXISTS external_key text;

-- Idempotent, and verified so: re-running DROP NOT NULL on an already-nullable
-- column is accepted and does nothing.
ALTER TABLE sap_system ALTER COLUMN sid    DROP NOT NULL;
ALTER TABLE sap_system ALTER COLUMN client DROP NOT NULL;

-- DATA FIRST, AND LOUDLY. The shape CHECK below demands `sid <> ''`, so it will
-- refuse to apply to any deployment already holding an empty-string sid — and the
-- two upgrade paths fail DIFFERENTLY: server/db.py runs this file in one
-- transaction (everything rolls back, nothing applied), while the CI job runs it
-- under psql statement-per-transaction (the ALTERs above stay, the CHECK does not
-- — a half-migrated database). Neither failure explains itself. This does.
DO $$
DECLARE broken int;
BEGIN
    SELECT count(*) INTO broken FROM sap_system
     WHERE platform = 'abap'
       AND (sid IS NULL OR sid = '' OR client IS NULL OR client = '');
    IF broken > 0 THEN
        RAISE EXCEPTION
            'sap_system holds % ABAP row(s) with an empty or missing sid/client. '
            'Decision D8 cannot be applied over them: an empty sid produces the '
            'same finding fingerprint as every other empty sid, which is the '
            'collision this migration exists to remove. Give each row a real sid '
            'and client, or delete the rows, then re-run.', broken;
    END IF;
END $$;

ALTER TABLE sap_system DROP CONSTRAINT IF EXISTS sap_system_platform_check;
ALTER TABLE sap_system ADD CONSTRAINT sap_system_platform_check
    CHECK (platform IN ('abap', 'btp', 'successfactors', 'concur', 'ias',
                        'cloud_alm', 'ariba', 'fieldglass'));

ALTER TABLE sap_system DROP CONSTRAINT IF EXISTS sap_system_shape_check;
ALTER TABLE sap_system ADD CONSTRAINT sap_system_shape_check CHECK (
    (platform =  'abap' AND sid <> '' AND client <> ''
                       AND sid IS NOT NULL AND client IS NOT NULL)
 OR (platform <> 'abap' AND external_key <> '' AND external_key IS NOT NULL));

DROP INDEX IF EXISTS sap_system_tenant_key;
CREATE UNIQUE INDEX sap_system_tenant_key
    ON sap_system (landscape_id, platform, external_key)
    NULLS NOT DISTINCT
    WHERE platform <> 'abap';

-- ---------------------------------------------------------------------
--  Installed software components  (CVERS)
-- ---------------------------------------------------------------------
--
-- WHAT THIS IS FOR. A check that looks for something introduced in a particular
-- release has three possible relationships to a system: it applies, it cannot
-- apply, or we do not know. Without this table only the first two are
-- expressible, and "we do not know" collapses into one of them — silently, and
-- in whichever direction the author happened to code. See
-- modules/base_auditor.py release_gate.
--
-- DECLARED HERE, IN THE MIGRATIONS SECTION, AND NOT UP WITH THE OTHER TABLES.
-- A CREATE TABLE up there is a no-op on every deployed database, which is fine
-- for a table nobody has yet — but it also means the indexes and constraints
-- below it would never be applied on an upgrade. Keeping the whole object in one
-- place, in the section that runs on both paths, is the idiom this file now uses
-- for anything added after the first release.
CREATE TABLE IF NOT EXISTS system_component (
    id            bigserial PRIMARY KEY,
    system_id     bigint      NOT NULL REFERENCES sap_system(id) ON DELETE CASCADE,
    -- SAP_BASIS, SAP_ABA, SAP_APPL, S4CORE, SAP_GWFND … the CVERS component name.
    component     text        NOT NULL CHECK (component <> ''),
    -- The release as SAP writes it: '750', '7.50' and '0750' are the same
    -- release. Stored VERBATIM rather than normalised, because the customer's own
    -- export is the evidence and rewriting it would make the stored value
    -- disagree with the file it came from. Comparison normalises at read time —
    -- see BaseAuditor._release_key, which exists because "750" < "8" as strings.
    release       text        NOT NULL CHECK (release <> ''),
    -- Support package level, where the export carries one.
    sp_level      text,
    description   text,
    collected_at  timestamptz NOT NULL DEFAULT now(),
    -- One release per component per system. A second row for SAP_BASIS is not a
    -- second component, it is a re-import, and it must update rather than
    -- accumulate — otherwise a gate reading "the" release gets whichever row the
    -- query happened to return first.
    UNIQUE (system_id, component)
);

CREATE INDEX IF NOT EXISTS system_component_system_idx
    ON system_component (system_id);

-- ---------------------------------------------------------------------
--  Schema version
-- ---------------------------------------------------------------------

-- ── CRQ parameters: the CFO's own figures ───────────────────────────────────
--  INSERT-ONLY, NEVER UPDATED, AND THAT IS THE WHOLE DESIGN.
--
--  A quantification is only defensible if the answers behind it can be produced
--  months later, unchanged. If a row were updated in place, every historical
--  crq_result would silently start claiming it was computed from figures that did
--  not exist when it ran, and the trend chart would redraw its own past. So a
--  revision is a NEW ROW, and crq_result records which revision produced it.
--
--  This also disarms the trap in the trend line. Risk moves for two unrelated
--  reasons — findings changed, or somebody revised an input — and a reader seeing
--  one line cannot tell which. With the revision id stored per result, the chart
--  can BREAK the series wherever the parameters changed, so an input revision can
--  never be read as a security improvement.
CREATE TABLE IF NOT EXISTS crq_parameters (
    id            bigserial PRIMARY KEY,
    landscape_id  bigint NOT NULL REFERENCES landscape(id) ON DELETE CASCADE,
    -- The answers, keyed by modules/fair_loss_model.PARAMETER_KEYS. jsonb rather
    -- than 14 columns because the question set is expected to grow, and a schema
    -- migration per new question would guarantee the set never grows.
    answers       jsonb NOT NULL DEFAULT '{}'::jsonb,
    currency      text NOT NULL DEFAULT 'USD',
    note          text,
    created_by    text,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS crq_parameters_landscape_idx
    ON crq_parameters (landscape_id, created_at DESC);

CREATE TABLE IF NOT EXISTS schema_version (
    version    integer PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO schema_version (version) VALUES (1) ON CONFLICT DO NOTHING;
INSERT INTO schema_version (version) VALUES (2) ON CONFLICT DO NOTHING;
INSERT INTO schema_version (version) VALUES (3) ON CONFLICT DO NOTHING;

-- CRQ v2. crq_result gains the parameter revision that produced it and the model
-- version, so a stored figure stays explainable after the model moves on. Both are
-- nullable: rows written before this migration were computed from the illustrative
-- catalogue, and NULL says exactly that. Backfilling them with a revision they were
-- not computed from would be inventing provenance.
ALTER TABLE crq_result ADD COLUMN IF NOT EXISTS crq_parameters_id bigint;
ALTER TABLE crq_result ADD COLUMN IF NOT EXISTS model_version integer;
ALTER TABLE crq_result ADD COLUMN IF NOT EXISTS ale_p95 numeric;
ALTER TABLE crq_result ADD COLUMN IF NOT EXISTS p_no_loss numeric;
