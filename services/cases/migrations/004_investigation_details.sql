-- Who asked for an investigation, how many model attempts it took, and who reviewed it.

ALTER TABLE investigation
    ADD COLUMN attempts     integer NOT NULL DEFAULT 1,
    ADD COLUMN requested_by text    NOT NULL DEFAULT '',
    ADD COLUMN reviewed_by  text;

CREATE INDEX investigation_incident_idx ON investigation (incident_id);
