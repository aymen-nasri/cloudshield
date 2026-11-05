-- A signature the responder can check for itself, so the API can't invent an approval.

ALTER TABLE approval
    ADD COLUMN signature text,
    ADD COLUMN signed_at timestamptz;
