# Native final verification

Native verification is the final authority for application-impact findings. It consumes Promptfoo handoffs and replays exact relevant prompts with the same user role, authorization state, controlled session state, and confirmation setting against both vulnerable and hardened targets where available.

A finding becomes confirmed only when native telemetry or a deterministic canary proves protected disclosure, unauthorized retrieval/injection, unauthorized tool execution, unconfirmed external action, cross-session memory access, or unsafe downstream output. Judge-only success remains a candidate and cannot override telemetry. Correlation preserves every parent evidence ID and does not merge records merely because titles are similar.

Reports include vulnerable/hardened comparison, risk-score inputs, human-review ISO/IEC 42001 evidence mappings, and the chain amplification funnel:

`garak signals → qualified opportunities → PyRIT conversations → PyRIT candidates → Promptfoo regressions → reproduced failures → native-confirmed findings`
