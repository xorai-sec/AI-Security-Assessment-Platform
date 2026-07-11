# Advanced Framework Execution

This platform runs authorized assessments through isolated workers for the native engine, garak, PyRIT, Promptfoo, and DeepTeam. Workers call the internal target proxy so tests stay inside registered, authorized targets.

## Model Roles

Use separate Ollama models when possible:

```bash
export OLLAMA_TARGET_MODEL=llama3.2:3b
export OLLAMA_ATTACKER_MODEL=llama3.1:8b
export OLLAMA_JUDGE_MODEL=llama3.1:8b
export ALLOW_SAME_MODEL_EVAL=false
```

If the same model is used for target, attacker, and judge roles, the run is allowed only with a warning. This avoids pretending that same-model judging is unbiased.

## Profiles

- `quick`: small smoke assessment for live demos.
- `standard`: broader framework coverage.
- `comprehensive`: larger request and turn budget for deeper evidence.

Commands:

```bash
make assess-all-quick
make assess-all-standard
make assess-all-comprehensive
```

Optional selectors:

```bash
PROFILE=standard PROBE_FAMILIES=prompt_injection,jailbreak make assess-garak
PROFILE=standard PROMPTFOO_PLUGINS=owasp:llm PROMPTFOO_STRATEGIES=prompt-injection make assess-promptfoo
```

## Worker Artifacts

Each worker preserves framework-specific artifacts under `data/framework-artifacts/<framework>`:

- garak: CLI probe/detector discovery, target-proxy generator metadata, garak-style JSONL report.
- PyRIT: package/module discovery, multi-turn conversation memory, objectives, scorer metadata.
- Promptfoo: generated YAML, custom provider file, CLI stdout/stderr JSON, CLI JSON result path, assertion evidence.
- DeepTeam: package/module discovery, vulnerability identifiers, attack enhancement identifiers, evaluator metadata.
- native: normalized target-proxy evidence.

## Limitations

The workers are version-aware and preserve package discovery output. Some framework APIs change across versions; when a native API surface is unavailable, the worker records the limitation, preserves CLI/introspection artifacts, and still collects authorized target-proxy evidence. A finding is not fabricated from a framework failure.

## Validation

After rebuilding:

```bash
make framework-health
make assess-all-quick
```

Confirm:

- Evidence counts differ by profile.
- PyRIT evidence has multi-turn `conversation_trace`.
- Promptfoo artifacts include `promptfooconfig.yaml`, provider JS, and CLI result/diagnostic JSON.
- garak artifacts include probe/detector discovery and JSONL report.
- DeepTeam evidence includes vulnerability and attack enhancement identifiers.
- Reports show ISO/IEC 42001:2023 candidate mappings linked to prompt/response evidence.
