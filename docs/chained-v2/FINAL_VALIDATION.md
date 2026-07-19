# Chained red-team v2 final validation

Validation date: 2026-07-19. Branch: `codex/chained-redteam-v2`.

## Results

| Check | Result |
|---|---|
| Python unit/integration tests | PASS — 49 passed |
| Web production build | PASS |
| Docker Compose configuration (base and frameworks overlay) | PASS |
| Promptfoo lockfile dry-run | PASS (validated previously) |
| Full Ruff check/format | BLOCKED — existing violations in workers |
| Full mypy | BLOCKED — duplicate `app` modules under worker directories |
| Docker image build/start | BLOCKED — Docker socket/BuildKit filesystem permissions |
| `make migrate` | BLOCKED — alembic unavailable in active interpreter |
| framework health/garak/PyRIT/Promptfoo/chain/hardened commands | BLOCKED — httpx unavailable in active interpreter; Docker unavailable |

The requested three vulnerable/hardened end-to-end runs, specialized model invocations, causal handoff proof, native-confirmed vulnerability count, and hardened comparison could not be reproduced in this environment. Existing stored artifacts are not substituted for a fresh validation run.

## Security checks

Unit coverage includes SSRF/target-security, malicious output handling, handoff integrity, model-role separation, garak qualification, PyRIT attacker behavior, Promptfoo local generation, and native telemetry authority. Container scans, live framework scans, and Dockerfile runtime checks remain blocked by unavailable Docker execution.

Decision evidence is preserved honestly; no certification or production-readiness claim is made.
