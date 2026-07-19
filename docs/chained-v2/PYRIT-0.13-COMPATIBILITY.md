# PyRIT 0.13.0 compatibility

The worker is pinned to `pyrit==0.13.0`. The old deep import paths are absent,
but runtime discovery must resolve the official public exports from
`pyrit.executor.attack`.

The current supported selection is:

| Selection | PyRIT class | Status |
|---|---|---|
| `prompt_sending` | `pyrit.executor.attack.PromptSendingAttack` | supported |
| `red_teaming` | `pyrit.executor.attack.RedTeamingAttack` | supported when runtime export resolves |
| `crescendo` | `pyrit.executor.attack.CrescendoAttack` | supported when runtime export resolves |
| `tap` | `pyrit.executor.attack.TAPAttack` | supported when runtime export resolves |

The worker records the requested selection, resolved public export and PyRIT
version. An unavailable selection produces an explicit stage error. It never
silently substitutes PromptSending. Runtime startup discovery reports each
export and its constructor signature.
