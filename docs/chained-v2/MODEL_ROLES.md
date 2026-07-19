# Auditable model-role gateway

The assessment stack now has a provider-neutral gateway for five independent
roles: attacker, judge, optional planner, embedding, and target. The gateway
supports Ollama (`/api/generate`) and OpenAI-compatible chat completion
endpoints. It is intentionally separate from PyRIT and Promptfoo execution;
their attack behavior is unchanged in this step.

## Configuration

Set model names and endpoints independently in `.env`:

```dotenv
ATTACKER_MODEL=red-agent:12b-q4km
ATTACKER_BASE_URL=http://attacker-model:8000/v1
JUDGE_MODEL=qwen3guard-judge:4b-q4km
JUDGE_BASE_URL=http://judge-model:8000/v1
PLANNER_MODEL=redsage-planner:8b-q4km
PLANNER_BASE_URL=http://planner-model:8000/v1
PLANNER_LLM_ENABLED=false
EMBEDDING_MODEL=nomic-embed-text

The verified community GGUF manifest and import procedure are in
`config/models/specialized-model-manifest.json` and
`scripts/import_specialized_gguf.sh`. GGUF files remain outside Git under
`SPECIALIZED_MODEL_DIR` and are mounted read-only into Ollama.
EMBEDDING_BASE_URL=http://ollama:11434
REQUIRE_DISTINCT_MODEL_ROLES=true
ALLOW_SAME_MODEL_EVAL=false
PROMPTFOO_DISABLE_REDTEAM_REMOTE_GENERATION=true
```

Required attacker and judge roles fail closed when explicitly enforced. The
only development fallback is `ALLOW_MODEL_ROLE_FALLBACK=true`; evidence is
then marked `role_gateway_limited` and must not be treated as a full
specialized-model assessment.

## Controls and evidence

The gateway enforces bounded timeouts, retries, input/output character limits,
provider-specific request construction, and optional structured JSON parsing.
Every invocation receives a UUID and records role, model, provider type,
timestamps, latency, request/response hashes, token usage when returned, and
success/error status. Authorization headers, tokens, and hidden chain-of-
thought are never stored.

`ModelManifest` supports source revision, SHA-256, quantization, and license
provenance fields. Populate these fields for every production model so an
assessment can be reproduced.

## Dependency reproducibility

PyRIT is pinned to `0.13.0`. Promptfoo is pinned to `0.121.18`; its lockfile
must be generated in a network-enabled environment with:

```bash
cd workers/promptfoo-worker
npm install --package-lock-only --ignore-scripts
npm ci --ignore-scripts
```

Do not use `latest` for runtime dependencies. Remote Promptfoo red-team
generation is disabled by configuration and must remain disabled for local
authorized assessments.
