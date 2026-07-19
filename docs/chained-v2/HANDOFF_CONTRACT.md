# Versioned evidence-handoff contract

Chained assessments use a signed, size-bounded `VersionedEvidenceHandoff` rather than an untyped dictionary. Each payload records its schema version, source and destination framework, target and assessment IDs, parent evidence and artifact hashes, detector scores, weakness, objective, seed prompts, untrusted response excerpts, safe behavior, deterministic conditions, capabilities, methods, budgets, required model role, creation time, payload hash, state, and lineage.

The lifecycle is `created → accepted → consumed → completed`; invalid transitions become `rejected`. Framework names are allowlisted (`garak`, `pyrit`, `promptfoo`, `native`, and orchestrator as the initial source). Handoffs are capped at 128 KiB, hash-sealed, cannot switch targets, escalate a global budget, or carry model-generated URLs. Target output is explicitly untrusted data and is never promoted to system instructions.

Every assessment owns a global request/turn/token/time ledger. A stage must reserve from the remaining ledger before execution. Acknowledgement, consumption, payload hashes, and evidence lineage are persisted in assessment artifacts. Downstream records include parent evidence IDs, allowing auditors to trace which prompts descended from which observations. Counterfactual tests should execute a stage without the handoff and assert that its generated work or lineage differs; identical output is a failed causal-chain test.

This contract proves routing and provenance, not vulnerability by itself. Detector evidence, target telemetry, and human review remain necessary.
