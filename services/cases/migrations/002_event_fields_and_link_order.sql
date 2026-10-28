-- Fields the services need to rebuild a NormalizedEvent and a case's link order exactly.

ALTER TABLE event
    ADD COLUMN title         text NOT NULL DEFAULT '',
    ADD COLUMN severity      text NOT NULL DEFAULT 'medium',
    ADD COLUMN pod_uid       text,
    ADD COLUMN instance_id   text,
    ADD COLUMN principal_arn text;

-- Correlation looks up open cases by these keys (rules C-01..C-03).
CREATE INDEX event_pod_uid_idx       ON event (pod_uid)       WHERE pod_uid IS NOT NULL;
CREATE INDEX event_instance_id_idx   ON event (instance_id)   WHERE instance_id IS NOT NULL;
CREATE INDEX event_principal_arn_idx ON event (principal_arn) WHERE principal_arn IS NOT NULL;

-- Links are shown in the order they were made; C-00 (the event that opened the case) comes first.
ALTER TABLE incident_event
    ADD COLUMN linked_at timestamptz NOT NULL DEFAULT clock_timestamp();

CREATE INDEX incident_status_idx ON incident (status);
