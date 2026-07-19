# DeepTeam removal from the active assessment stack

DeepTeam was removed from the active product in the chained-assessment v2
baseline branch. The baseline review found that it added a worker, Compose
profile, environment variables, Make targets, planner fields, inspection and
permission scripts, and documentation without strengthening the validated
garak → PyRIT → Promptfoo → native workflow.

## What changed

- Deleted `workers/deepteam-worker/` and its inspection script.
- Removed the DeepTeam Compose service and API worker URL/configuration.
- Removed DeepTeam environment variables and concurrency settings.
- Removed Make targets, framework self-test defaults, and planner selection
  fields.
- Removed DeepTeam artifact-directory setup and permission handling.
- Removed the DeepTeam framework row from the active README/support material.
- Updated the active adaptive handoff test to use only the four supported
  frameworks.

## Responsibility replacement

- Garak remains responsible for broad probe discovery and detector signals.
- PyRIT remains responsible for attacker-driven exploitation work currently
  supported by its worker.
- Promptfoo remains responsible for repeatable generated configuration and
  assertion/regression execution.
- Native workers remain responsible for deterministic technical verification,
  authorization, retrieval, memory, and tool telemetry checks.

This removal does not implement new attacker-model routing or change the
existing PyRIT/Promptfoo execution semantics.

## Migration impact

Remove `deepteam` from any framework request lists and replace it with one of
`garak`, `pyrit`, `promptfoo`, or `native` according to the assessment goal.
The `deepteam-worker` service, port 8094, environment variables, Make targets,
and artifact directory are no longer valid. Existing DeepTeam artifact files
are not deleted by this change; they remain operator-owned historical data.

## Historical references

Some historical Phase 3/Phase 4 reports and planning documents retain the name
to preserve audit history. They are explicitly marked historical or superseded
and must not be read as evidence of current support. The active README,
Compose files, Makefile, planner, registry, tests, and runtime scripts contain
no DeepTeam integration.
