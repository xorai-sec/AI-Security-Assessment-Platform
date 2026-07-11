# Phase 3 Target Support Matrix

| Target type | Status | Capabilities | Validation status |
|---|---|---|---|
| EnterpriseAssist | Implemented and locally tested | Chat, RAG, tools, memory, telemetry, white-box evidence | Tested in previous Docker run; adapter path added in this phase |
| OpenAI-compatible | Implemented with local fixture | Chat, multi-turn, model metadata, token usage where returned | Fixture endpoint added; Docker validation pending |
| Ollama | Implemented, runtime-dependent | Local model chat and model availability check | Requires Ollama service/model on host |
| vLLM | Implemented through OpenAI-compatible adapter | OpenAI-compatible local serving | Requires vLLM runtime |
| Custom REST | Implemented with local fixture | Configurable request/response mapping, optional telemetry | Fixture endpoint added; Docker validation pending |
| Generic RAG | Implemented through telemetry-dependent Custom REST profile | Chat and optional retrieval telemetry | Depends on target telemetry schema |
| Generic Agent | Implemented through telemetry-dependent Custom REST profile | Chat and optional tool/action telemetry | Depends on target telemetry schema |

