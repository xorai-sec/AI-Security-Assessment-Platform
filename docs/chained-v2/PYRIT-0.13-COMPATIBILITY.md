# PyRIT 0.13.0 compatibility

The worker is pinned to `pyrit==0.13.0`. Runtime inspection of that package
verified `pyrit.executor.attack.single_turn.prompt_sending.PromptSendingAttack`.
The previously documented `red_teaming`, `crescendo`, and `tap` module paths
are absent from 0.13.0 and are therefore rejected by the API. They are not
emulated with a custom loop and never silently fall back to PromptSending.

The current supported selection is:

| Selection | PyRIT class | Status |
|---|---|---|
| `prompt_sending` | `pyrit.executor.attack.single_turn.prompt_sending.PromptSendingAttack` | supported |
| `red_teaming` | no public class found in 0.13.0 | rejected |
| `crescendo` | no public class found in 0.13.0 | rejected |
| `tap` | no public class found in 0.13.0 | rejected |

The worker records the requested selection, resolved class and PyRIT version.
An unavailable selection produces an explicit stage error. To add a
multi-turn technique later, first pin a release that actually exports it and
add a runtime import/constructor smoke test against that exact package.
