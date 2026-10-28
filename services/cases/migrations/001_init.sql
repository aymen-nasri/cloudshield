-- CloudShield case store. PostgreSQL 16.
-- Mirrors the data model in the README. Applied by the M2 PostgreSQL store.
-- IDs are prefixed, time-sortable strings (evt_..., case_..., prp_...), see services/common/ids.py.

CREATE TABLE incident (
    id          text PRIMARY KEY,
    title       text        NOT NULL,
    status      text        NOT NULL DEFAULT 'open'
                CHECK (status IN ('open', 'contained', 'closed')),
    priority    smallint    NOT NULL DEFAULT 3,
    assignee    text,
    account_id  text,
    cluster     text,
    opened_at   timestamptz NOT NULL DEFAULT now(),
    closed_at   timestamptz
);

CREATE TABLE event (
    event_id          text PRIMARY KEY,
    dedup_key         text        NOT NULL UNIQUE,  -- second line of defense against duplicate delivery
    source            text        NOT NULL,
    source_event_id   text        NOT NULL,
    schema_version    text        NOT NULL,
    event_time        timestamptz NOT NULL,
    ingest_time       timestamptz NOT NULL,
    account_id        text,
    cluster           text,
    namespace         text,
    resource_id       text,
    identity_id       text,
    event_type        text        NOT NULL,
    original_severity text        NOT NULL,
    raw_evidence_uri  text        NOT NULL,
    checksum_sha256   text        NOT NULL,
    ocsf              jsonb       NOT NULL
);
CREATE INDEX event_time_idx ON event (event_time);
CREATE INDEX event_resource_idx ON event (resource_id);

CREATE TABLE incident_event (
    incident_id text    NOT NULL REFERENCES incident (id),
    event_id    text    NOT NULL REFERENCES event (event_id),
    link_rule   text    NOT NULL,
    confidence  numeric NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    rationale   text    NOT NULL,
    PRIMARY KEY (incident_id, event_id)
);

CREATE TABLE entity (
    id           text PRIMARY KEY,
    kind         text        NOT NULL,  -- pod, deployment, service_account, iam_role, instance, ...
    external_id  text        NOT NULL,
    account_id   text,
    cluster      text,
    namespace    text,
    attributes   jsonb       NOT NULL DEFAULT '{}',
    observed_at  timestamptz NOT NULL,
    UNIQUE (kind, external_id)
);

CREATE TABLE entity_edge (
    from_entity  text        NOT NULL REFERENCES entity (id),
    to_entity    text        NOT NULL REFERENCES entity (id),
    relation     text        NOT NULL,  -- runs_on, belongs_to, uses_identity, observed_communication, ...
    assurance    text        NOT NULL CHECK (assurance IN ('configured', 'observed', 'possible', 'proven')),
    valid_from   timestamptz,
    valid_to     timestamptz,
    evidence_ids text[]      NOT NULL DEFAULT '{}',
    PRIMARY KEY (from_entity, to_entity, relation)
);

CREATE TABLE event_entity (
    event_id  text NOT NULL REFERENCES event (event_id),
    entity_id text NOT NULL REFERENCES entity (id),
    PRIMARY KEY (event_id, entity_id)
);

CREATE TABLE investigation (
    id                text PRIMARY KEY,
    incident_id       text  NOT NULL REFERENCES incident (id),
    model_id          text  NOT NULL,
    prompt_version    text  NOT NULL,
    retrieved_doc_ids jsonb NOT NULL DEFAULT '[]',
    output            jsonb NOT NULL,
    review_status     text  NOT NULL DEFAULT 'unreviewed'
                      CHECK (review_status IN ('unreviewed', 'accepted', 'rejected')),
    created_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE response_proposal (
    id              text PRIMARY KEY,
    incident_id     text        NOT NULL REFERENCES incident (id),
    action_type     text        NOT NULL,
    action_class    text        NOT NULL,
    target          jsonb       NOT NULL,
    environment     text        NOT NULL,
    impact_preview  jsonb       NOT NULL DEFAULT '{}',
    proposal_hash   text        NOT NULL,
    idempotency_key text        NOT NULL UNIQUE,
    state           text        NOT NULL,
    expires_at      timestamptz NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE approval (
    id            text PRIMARY KEY,
    proposal_id   text        NOT NULL REFERENCES response_proposal (id),
    approver      text        NOT NULL,
    decision      text        NOT NULL CHECK (decision IN ('approve', 'reject')),
    justification text        NOT NULL,
    bound_hash    text        NOT NULL,
    decided_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (proposal_id, approver)
);

CREATE TABLE execution (
    id                text PRIMARY KEY,
    proposal_id       text NOT NULL UNIQUE REFERENCES response_proposal (id),  -- at most one execution
    executor_identity text NOT NULL,
    status            text NOT NULL,
    result            jsonb,
    started_at        timestamptz NOT NULL DEFAULT now(),
    finished_at       timestamptz
);

CREATE TABLE verification (
    id           text PRIMARY KEY,
    execution_id text    NOT NULL REFERENCES execution (id),
    check_name   text    NOT NULL,
    passed       boolean,  -- NULL = check skipped, with the reason in observed
    observed     jsonb   NOT NULL DEFAULT '{}'
);

CREATE TABLE audit_log (
    seq        bigint PRIMARY KEY,
    ts         timestamptz NOT NULL,
    actor_type text        NOT NULL CHECK (actor_type IN ('human', 'service', 'model')),
    actor_id   text        NOT NULL,
    action     text        NOT NULL,
    details    jsonb       NOT NULL,
    prev_hash  text        NOT NULL,
    hash       text        NOT NULL UNIQUE
);

-- The audit log is append-only: the application role may INSERT and SELECT, never UPDATE or DELETE.
REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM PUBLIC;
