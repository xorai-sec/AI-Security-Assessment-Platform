# Assessment Orchestration

The current orchestrator is synchronous and API-driven. It validates scope, chooses supported native campaigns based on target capabilities, sends prompts through the target adapter, evaluates responses, creates findings, maps ISO candidates and writes reports.

Redis worker orchestration is planned and blocked until queue models and cancellation are implemented.

