# Advanced Framework Execution

> Historical document. DeepTeam references are retained for migration context
> only; it is not part of the active product.

This platform runs authorized assessments through isolated workers for the native engine, garak, PyRIT, Promptfoo, and DeepTeam. Workers call the internal target proxy so tests stay inside registered, authorized targets.

Strict framework proof is enforced. A worker must set `native_engine_invoked=true` and `fallback_used=false` before its output should be treated as native framework execution. Discovery output, normalized proxy evidence, or framework-shaped files are not enough.

## Model Roles

Use separate Ollama models when possible:

```bash
export OLLAMA_TARGET_MODEL=llama3.2:3b
export OLLAMA_ATTACKER_MODEL=llama3.1:8b
export OLLAMA_JUDGE_MODEL=llama3.1:8b
export ALLOW_SAME_MODEL_EVAL=false
```

If the same model is used for target, attacker, and judge roles, the run is allowed only with a warning. This avoids pretending that same-model judging is unbiased.

To pull the configured Ollama model roles into the running compose stack:

```bash
make setup-ollama-models
```

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

- native: platform-native target-proxy evidence with `native_engine_invoked=true`.
- Promptfoo: generated YAML, custom provider file, CLI stdout/stderr JSON, CLI JSON result path, assertion evidence. CLI failure is a failed run; no fallback evidence is substituted.
- garak: CLI probe/detector discovery only until a real target-proxy `garak` Generator, installed Probe classes, installed Detector classes, and unmodified native garak report preservation are implemented.
- PyRIT: package/module discovery only until a real PyRIT PromptTarget, orchestrator/executor, memory, converter, and scorer integration is implemented.
- DeepTeam: package/module discovery only until the installed DeepTeam scan/red-team API, vulnerability classes, attack enhancements, target callback, and native evaluator objects are implemented.

## Limitations

The workers are version-aware and preserve package discovery output. Some framework APIs change across versions. In strict mode, unavailable native framework execution is recorded as a failed worker run with `native_engine_invoked=false`. The platform does not fabricate success from framework failures and does not silently replace failed Promptfoo CLI runs with fallback evidence.

Every framework execution result and normalized evidence item includes:

- `native_engine_invoked`
- `native_command_or_api`
- `native_framework_version`
- `native_artifact_path`
- `native_plugin_identifiers`
- `fallback_used`
- `fallback_reason`

## Validation

After rebuilding:

```bash
make framework-health
make assess-all-quick
```

Confirm:

- Promptfoo artifacts include `promptfooconfig.yaml`, provider JS, and CLI result/diagnostic JSON.
- Promptfoo successful executions show `native_engine_invoked=true` and `fallback_used=false`.
- garak, PyRIT, and DeepTeam currently fail strict native acceptance until their official engine adapters are implemented.
- Reports show ISO/IEC 42001:2023 candidate mappings linked to prompt/response evidence.
