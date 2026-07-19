# Chained Assessment v2 Baseline

Validation date: 2026-07-19
Branch: `codex/chained-redteam-v2`

This document records the repository baseline before any chained-assessment
redesign. Existing worktree changes and generated assessment artifacts were
preserved; this baseline does not remove DeepTeam or change framework behavior.

## Repository and architecture inventory

- API/orchestration: `apps/api/app`, `packages/security_assurance/`
- Workers: `workers/native-worker`, `workers/garak-worker`,
  `workers/pyrit-worker`, `workers/promptfoo-worker`, and
  `workers/deepteam-worker`
- Framework dispatch: `packages/security_assurance/framework_manager.py`
- Handoff construction and analysis:
  `packages/security_assurance/evidence_handoff.py`
- Planner: `packages/security_assurance/adaptive_planner.py`
- Assessment entry point: `scripts/frameworks/assess_frameworks.py`
- Frontend: `apps/web`
- Compose services: API, EnterpriseAssist, PostgreSQL, Redis, web, and the
  framework overlay workers (including an optional DeepTeam profile)
- Model roles: `OLLAMA_TARGET_MODEL`, `OLLAMA_ATTACKER_MODEL`,
  `OLLAMA_JUDGE_MODEL`, `OLLAMA_PLANNER_MODEL`, and
  `OLLAMA_EMBEDDING_MODEL`

The stable framework order is declared as `garak`, `pyrit`, `promptfoo`,
`native`. Adaptive modes create `HandoffPlan` objects. The
`complete-pentest` path currently selects the next framework in that order and
does not create a handoff payload for the stage.

## Validation results

| Check | Result | Command |
|---|---|---|
| Backend lint | PASS | `conda run -n jais310 python -m ruff check apps packages scripts tests` |
| Type checking | PASS | `conda run -n jais310 python -m mypy packages apps/api/app apps/enterprise-assist/app` |
| Unit tests | PASS (21) | `conda run -n jais310 python -m pytest tests/unit -q` |
| Integration tests | PASS (1) | `conda run -n jais310 python -m pytest tests/integration -q` |
| Frontend build | PASS | `npm --prefix apps/web run build` |
| Compose config | PASS | `docker compose config` |
| Framework Compose config | PASS | `docker compose -f docker-compose.yml -f docker-compose.frameworks.yml config` |
| Docker service health | BLOCKED | Docker socket permission denied |
| Vulnerable chain | BLOCKED | Requires running Docker services and an approved target |
| Hardened chain | BLOCKED | Requires running Docker services and an approved hardened target |

Docker was not available to this execution environment:

```text
permission denied while trying to connect to the Docker API at unix:///var/run/docker.sock
```

Therefore no Docker build, service health, current vulnerable assessment, or
hardened assessment result is claimed by this baseline.

## Existing worktree state

The branch was created from the fetched `origin/main`. Pre-existing modified
files and untracked assessment artifacts were intentionally not staged or
discarded. Only this baseline documentation is part of the baseline commit.

## Reproduction commands when Docker access is available

```bash
docker compose build
docker compose up -d
docker compose ps
docker compose -f docker-compose.yml -f docker-compose.frameworks.yml up -d
make framework-health
TARGET_ID=<approved-target-id> make assess-complete-pentest
TARGET_ID=<approved-hardened-target-id> make assess-complete-pentest
docker compose down
```

The two assessment commands require written authorization and must be run only
against approved synthetic or owned targets.
