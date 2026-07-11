# Phase 4 Framework Execution Plan

## Current repository state

Phase 3 at `a7bdcbe` provided target adapters, target manager APIs, target registration UI, native target-based assessments, evidence, ISO mapping and reports.

Phase 4 adds isolated framework worker services, a shared worker protocol, an internal target proxy and multi-framework orchestration endpoints.

## Existing reusable components

- Target adapters for EnterpriseAssist, OpenAI-compatible/vLLM, Ollama and Custom REST.
- Evidence hashing and deterministic canary confirmation.
- Existing native campaigns and report generation.
- Docker Compose API, web, Redis, PostgreSQL and EnterpriseAssist services.

## Framework dependency requirements

| Framework | Isolation | Dependency |
|---|---|---|
| native | Python worker | platform code only |
| garak | Python worker | `garak==0.13.0` |
| PyRIT | Python worker | `pyrit` package, version detected at runtime |
| Promptfoo | Node worker | `promptfoo` npm package |
| DeepTeam | Python worker | `deepteam` package, version detected at runtime |

The main API environment does not install these framework packages.

## Isolation strategy

Each framework has its own worker container under `workers/`. Workers expose `/health`, `/version`, `/capabilities`, `/validate-campaign`, `/execute`, `/cancel`, `/status` and `/result`.

## Worker communication protocol

Workers receive a framework execution request and communicate with targets only through:

```text
POST /internal/targets/{target_id}/message
```

The proxy is protected by `TARGET_PROXY_SECRET`.

## Target bridging strategy

Framework workers never receive stored client credentials. The main API owns target adapters, credentials, URL policy and sanitization.

## Raw result formats

Workers preserve raw JSON/JSONL artifacts under `data/framework-artifacts/`.

## Normalization strategy

Worker results normalize to `NormalizedFrameworkEvidence` with framework, target, prompt, response, telemetry, confirmation, confidence, evidence limitations and artifact references.

## Testing plan

1. Build API/web.
2. Build framework worker containers.
3. Run `make framework-health`.
4. Register EnterpriseAssist.
5. Run `make assess-all`.
6. Generate PDF reports and evidence package.
7. Record Ubuntu output in `docs/phase4/END_TO_END_TEST_RESULTS.md`.

## GPU and CPU assumptions

Framework execution is CPU-first. GPU is only required for optional local attacker/scorer/target models.

## Known compatibility risks

- PyRIT and DeepTeam package versions may require Python version changes or external scorer/evaluator model configuration.
- Promptfoo currently requires modern Node; Docker worker uses Node 24.
- garak probe APIs change between releases. This worker validates CLI availability and uses proxy-based prompts for controlled execution.

