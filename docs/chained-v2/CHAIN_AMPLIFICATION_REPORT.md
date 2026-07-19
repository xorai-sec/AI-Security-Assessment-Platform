# Chain amplification report

The implemented funnel is:

`garak signals → qualified opportunities → PyRIT conversations → PyRIT candidates → Promptfoo regressions → reproduced failures → native-confirmed findings`

The application records these counts in `adaptive_artifacts.chain_amplification_funnel` and preserves parent evidence IDs in each handoff. Unit tests prove that duplicate/low-quality garak signals are rejected, handoffs preserve lineage, PyRIT and Promptfoo suites change when handoffs are absent, and judge-only positives cannot become native confirmations.

Fresh runtime counts and vulnerable-versus-hardened deltas are **not validated** in this environment because Docker and framework runtime dependencies were unavailable. They must be populated by a later authorized Ubuntu/Docker run; do not infer them from historical reports.
