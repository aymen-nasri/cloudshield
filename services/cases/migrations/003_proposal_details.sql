-- Fields the response API needs to rebuild a proposal, re-check approvals and show verification.

ALTER TABLE response_proposal
    ADD COLUMN requested_by   text  NOT NULL DEFAULT '',
    ADD COLUMN rationale      text  NOT NULL DEFAULT '',
    ADD COLUMN parameters     jsonb NOT NULL DEFAULT '{}',
    ADD COLUMN dry_run_passed boolean,
    ADD COLUMN policy         jsonb;  -- the last policy decision, reasons and approval requirements

CREATE INDEX response_proposal_incident_idx ON response_proposal (incident_id);

ALTER TABLE approval
    ADD COLUMN approver_roles text[] NOT NULL DEFAULT '{}';

-- The verifier's notes for checks that were skipped or failed.
ALTER TABLE verification
    ADD COLUMN note text;
