# Phase 4 Release Blockers

Release decision: NOT READY

The current patch implements framework worker architecture and execution wrappers, but the platform is not ready for authorized multi-framework client testing until:

- Framework worker Docker images build successfully on Ubuntu.
- garak, PyRIT, Promptfoo and DeepTeam package versions are detected.
- At least one campaign from each framework executes against EnterpriseAssist through the internal target proxy.
- PostgreSQL repositories replace file-backed operational storage.
- Redis async queues, retries, cancellation, dead-letter handling and live progress are wired.
- Cross-framework finding correlation is completed.
- PDF reports are upgraded beyond minimal generated PDFs.
- Evidence package export policy is reviewed.

