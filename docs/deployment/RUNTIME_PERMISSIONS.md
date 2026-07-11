# Runtime Permissions

Framework workers run as non-root users and write raw artifacts under `data/framework-artifacts`.

The Docker framework profile mounts each worker to its own artifact directory:

- `native-worker` -> `data/framework-artifacts/native`
- `garak-worker` -> `data/framework-artifacts/garak`
- `pyrit-worker` -> `data/framework-artifacts/pyrit`
- `deepteam-worker` -> `data/framework-artifacts/deepteam`
- `promptfoo-worker` -> `data/framework-artifacts/promptfoo`

Do not run `chown -R` on the whole `data/framework-artifacts` directory for one worker. That can make the other workers unable to write their artifacts.

Default worker UID/GID is `1000:1000`, which matches the normal first Linux desktop user on the Ubuntu lab machine. Override it only when needed:

```bash
export WORKER_UID="$(id -u)"
export WORKER_GID="$(id -g)"
make prepare-runtime
make up-frameworks
```

Validate a running framework stack with:

```bash
make validate-artifact-permissions
```

The validation command performs a real write from each worker container to its own mounted artifact directory.
