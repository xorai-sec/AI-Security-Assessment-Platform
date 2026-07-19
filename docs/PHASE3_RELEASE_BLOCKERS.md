# Phase 3 Release Blockers

> Historical release record. DeepTeam references are superseded and do not
> describe current support.

Release decision: READY FOR AUTHORIZED CLIENT DEMONSTRATION WITH DOCUMENTED LIMITATIONS

## Blockers before authorized client assessment

- PostgreSQL data model and Alembic migrations are not wired.
- Redis worker queues, cancellation, retries, dead-letter handling, and live event streaming are not wired.
- garak, PyRIT, Promptfoo, and DeepTeam adapters are not validated in this new target abstraction.
- Credential protection is development-grade and must be replaced for enterprise use.
- PDF and evidence package generation are not implemented.
- Full end-to-end frontend tests are not implemented.
