# Analyst console

Planned for milestone M2. The console is a thin client over the core API:

| View | API |
|---|---|
| Case list | `GET /v1/cases` |
| Incident page (synopsis, entity chain, timeline, facts vs hypotheses, proposed action) | `GET /v1/cases/{id}`, `GET /v1/cases/{id}/timeline` |
| Coverage banner | `GET /v1/health/coverage` |
| Audit trail | `GET /v1/audit?case_id=` |

The layout follows the incident page mockup in the main README. Approve and reject buttons call
the M4 approval endpoints and always send the proposal hash the analyst was shown.
